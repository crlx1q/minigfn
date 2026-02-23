'use strict';

/**
 * mini GFN for Android phones via Webkey
 * Single-file backend (Express + ws optional dependency not required by core logic).
 *
 * Security goals (MVP):
 *  - Clients never see raw device Webkey URL/credentials.
 *  - All frame/input traffic goes through this server.
 *  - Session TTL enforced server-side (authoritative endAt).
 *  - Commands are whitelisted; no arbitrary shell from clients.
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const crypto = require('crypto');

// ------------------------------
// Configuration
// ------------------------------
const CONFIG = {
  PORT: Number(process.env.PORT || 3000),
  HOST: process.env.HOST || '0.0.0.0',
  DATA_DIR: process.env.DATA_DIR || path.join(__dirname, 'data'),

  SESSION_MINUTES_FREE: Number(process.env.SESSION_MINUTES_FREE || 30),
  SESSION_MINUTES_PRO: Number(process.env.SESSION_MINUTES_PRO || 180),

  HEARTBEAT_INTERVAL_MS: Number(process.env.HEARTBEAT_INTERVAL_MS || 15000),
  SESSION_WATCHDOG_MS: Number(process.env.SESSION_WATCHDOG_MS || 3000),

  FRAME_RATE_DEFAULT: Number(process.env.FRAME_RATE_DEFAULT || 3),

  AUTH_TOKEN_TTL_MS: Number(process.env.AUTH_TOKEN_TTL_MS || 1000 * 60 * 60 * 12), // 12h
  GAME_TOKEN_TTL_MS: Number(process.env.GAME_TOKEN_TTL_MS || 1000 * 60 * 5), // short-lived 5 min

  SESSION_SECRET: process.env.SESSION_SECRET || 'CHANGE_ME_super_secret',

  // Pro priority policy: 2 pro slots then 1 normal (if both queues have users).
  PRO_PRIORITY_RATIO: Number(process.env.PRO_PRIORITY_RATIO || 2),

  // Webkey behavior (path templates may differ by Webkey version)
  WEBKEY_TIMEOUT_MS: Number(process.env.WEBKEY_TIMEOUT_MS || 5000),

  GAMES: [
    {
      id: 'game1',
      title: 'Doodle Jump',
      image: '',
      packageName: 'com.lima.doodlejump',
      activity: '',
      orientation: 'portrait',
    },
    {
      id: 'game2',
      title: 'Angry Birds',
      image: '',
      packageName: 'com.rovio.angrybirds',
      activity: '',
      orientation: 'landscape',
    },
    {
      id: 'game3',
      title: 'Subway Surfers',
      image: '',
      packageName: 'com.kiloo.subwaysurf',
      activity: '',
      orientation: 'landscape',
    },
  ],

  // IMPORTANT: replace these URLs and credentials with real private network values.
  DEVICES_SEED: [
    {
      id: 'phone-1',
      name: 'Galaxy Ace #1',
      privateIp: '192.168.1.101',
      webkeyBaseUrl: 'http://192.168.1.101:7777',
      webkeyUser: 'admin',
      webkeyPassword: 'admin',
      webkeyToken: '',
      maintenance: false,
      supportedGames: ['game1', 'game2', 'game3'],
    },
    {
      id: 'phone-2',
      name: 'Galaxy Mini #2',
      privateIp: '192.168.1.102',
      webkeyBaseUrl: 'http://192.168.1.102:7777',
      webkeyUser: 'admin',
      webkeyPassword: 'admin',
      webkeyToken: '',
      maintenance: false,
      supportedGames: ['game1', 'game2'],
    },
  ],
};

const FILES = {
  users: path.join(CONFIG.DATA_DIR, 'users.json'),
  devices: path.join(CONFIG.DATA_DIR, 'devices.json'),
  sessions: path.join(CONFIG.DATA_DIR, 'sessions.json'),
  queue: path.join(CONFIG.DATA_DIR, 'queue.json'),
};

// ------------------------------
// Utility helpers
// ------------------------------
const now = () => Date.now();
const isoNow = () => new Date().toISOString();
const uid = (prefix = 'id') => `${prefix}_${crypto.randomBytes(8).toString('hex')}`;

function safeJsonParse(text, fallback) {
  try {
    return JSON.parse(text);
  } catch {
    return fallback;
  }
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(derivedKey.toString('hex'));
    });
  });
}

async function createPasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await hashPassword(password, salt);
  return { salt, hash, algo: 'scrypt' };
}

async function verifyPassword(password, rec) {
  if (!rec || !rec.salt || !rec.hash) return false;
  const hash = await hashPassword(password, rec.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(rec.hash, 'hex'));
}

function signAuthToken(payload, ttlMs) {
  const exp = now() + ttlMs;
  const body = Buffer.from(JSON.stringify({ ...payload, exp })).toString('base64url');
  const sig = crypto.createHmac('sha256', CONFIG.SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyAuthToken(token) {
  if (!token || typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const check = crypto.createHmac('sha256', CONFIG.SESSION_SECRET).update(body).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(check), Buffer.from(sig))) return null;
  const payload = safeJsonParse(Buffer.from(body, 'base64url').toString('utf8'), null);
  if (!payload || !payload.exp || payload.exp < now()) return null;
  return payload;
}

function getBearer(req) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

async function ensureDir(p) {
  await fsp.mkdir(p, { recursive: true });
}

async function readJsonFile(file, fallback) {
  try {
    const text = await fsp.readFile(file, 'utf8');
    return safeJsonParse(text, fallback);
  } catch {
    return fallback;
  }
}

async function writeJsonAtomic(file, value) {
  const tmp = `${file}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(value, null, 2), 'utf8');
  await fsp.rename(tmp, file);
}

// ------------------------------
// DataStore with debounced persistence
// ------------------------------
class DataStore {
  constructor() {
    this.users = [];
    this.devices = [];
    this.sessions = [];
    this.queue = [];
    this.saveTimer = null;
  }

  async init() {
    await ensureDir(CONFIG.DATA_DIR);
    this.users = await readJsonFile(FILES.users, []);
    this.devices = await readJsonFile(FILES.devices, []);
    this.sessions = await readJsonFile(FILES.sessions, []);
    this.queue = await readJsonFile(FILES.queue, []);

    // Seed first start
    if (!this.devices.length) {
      this.devices = CONFIG.DEVICES_SEED.map((d) => ({
        ...d,
        status: 'unknown',
        busy: false,
        currentSessionId: null,
        lastSeen: null,
        lastHeartbeatError: null,
        health: {
          battery: null,
          mem: null,
          cpu: null,
          raw: null,
        },
      }));
    }

    // Seed admin user if absent
    const hasAdmin = this.users.some((u) => u.role === 'admin');
    if (!hasAdmin) {
      const pw = await createPasswordRecord('admin123');
      this.users.push({
        id: uid('user'),
        username: 'admin',
        password: pw,
        role: 'admin',
        pro: true,
        createdAt: isoNow(),
      });
      console.log('[INIT] Seeded default admin: admin / admin123 (CHANGE IT)');
    }

    // On restart: finalize stale active sessions so no lingering access.
    let changed = false;
    for (const s of this.sessions) {
      if (s.status === 'active' || s.status === 'starting') {
        s.status = 'terminated';
        s.endedAt = isoNow();
        s.terminateReason = 'server_restart_cleanup';
        changed = true;
      }
    }
    for (const d of this.devices) {
      if (d.currentSessionId) {
        d.currentSessionId = null;
        d.busy = false;
        changed = true;
      }
    }
    if (changed) this.scheduleSave();

    await this.saveNow();
  }

  scheduleSave() {
    if (this.saveTimer) clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => {
      this.saveNow().catch((e) => console.error('saveNow error', e));
    }, 250);
  }

  async saveNow() {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
    }
    await Promise.all([
      writeJsonAtomic(FILES.users, this.users),
      writeJsonAtomic(FILES.devices, this.devices),
      writeJsonAtomic(FILES.sessions, this.sessions),
      writeJsonAtomic(FILES.queue, this.queue),
    ]);
  }
}

const db = new DataStore();

// ------------------------------
// Webkey adapter abstraction
// ------------------------------
class WebkeyAdapter {
  /**
   * IMPORTANT:
   * Webkey endpoints vary by version/build. Adjust path templates in one place here.
   * Fallbacks included: shell command endpoint + potential screen endpoint variants.
   */
  buildAuthHeaders(device) {
    const headers = {};
    if (device.webkeyToken) {
      headers['X-Auth-Token'] = device.webkeyToken;
    } else if (device.webkeyUser || device.webkeyPassword) {
      const basic = Buffer.from(`${device.webkeyUser || ''}:${device.webkeyPassword || ''}`).toString('base64');
      headers.authorization = `Basic ${basic}`;
    }
    return headers;
  }

  async request(device, method, endpoint, { query = null, body = null, timeoutMs = CONFIG.WEBKEY_TIMEOUT_MS, expectBinary = false } = {}) {
    const url = new URL(endpoint, device.webkeyBaseUrl);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method,
        headers: {
          ...this.buildAuthHeaders(device),
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!res.ok) {
        const txt = await res.text().catch(() => '');
        throw new Error(`Webkey ${method} ${url.pathname} -> ${res.status}: ${txt.slice(0, 200)}`);
      }

      if (expectBinary) {
        return {
          contentType: res.headers.get('content-type') || 'image/jpeg',
          buffer: Buffer.from(await res.arrayBuffer()),
        };
      }

      const ct = res.headers.get('content-type') || '';
      if (ct.includes('application/json')) return await res.json();
      return await res.text();
    } finally {
      clearTimeout(t);
    }
  }

  async sendShell(device, command) {
    // Common Webkey patterns; update as needed for your build.
    const attempts = [
      () => this.request(device, 'GET', '/shell', { query: { command } }),
      () => this.request(device, 'GET', '/api/shell', { query: { command } }),
      () => this.request(device, 'POST', '/api/execute', { body: { command } }),
    ];
    let lastErr = null;
    for (const fn of attempts) {
      try {
        return await fn();
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr || new Error('No working shell endpoint');
  }

  async getFrame(device) {
    // Different Webkey versions expose frame at different paths.
    const frameAttempts = [
      () => this.request(device, 'GET', '/screen.jpeg', { expectBinary: true }),
      () => this.request(device, 'GET', '/screenshot.jpg', { expectBinary: true }),
      () => this.request(device, 'GET', '/api/screen', { expectBinary: true }),
    ];
    let lastErr = null;
    for (const fn of frameAttempts) {
      try {
        return await fn();
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr || new Error('No frame endpoint works');
  }

  async startGame(device, game) {
    await this.screenOn(device);
    if (game.activity) {
      await this.sendShell(device, `am start -n ${game.packageName}/${game.activity}`);
    } else {
      // fallback for unknown activity
      await this.sendShell(device, `monkey -p ${game.packageName} -c android.intent.category.LAUNCHER 1`);
    }
  }

  async stopGame(device, game) {
    if (!game || !game.packageName) return;
    await this.sendShell(device, `am force-stop ${game.packageName}`);
  }

  async sendInput(device, input) {
    // Only server calls this method after whitelist validation.
    if (input.type === 'tap') {
      return this.sendShell(device, `input tap ${Math.floor(input.x)} ${Math.floor(input.y)}`);
    }
    if (input.type === 'swipe') {
      return this.sendShell(device, `input swipe ${Math.floor(input.x1)} ${Math.floor(input.y1)} ${Math.floor(input.x2)} ${Math.floor(input.y2)} ${Math.floor(input.duration || 200)}`);
    }
    if (input.type === 'keyevent') {
      return this.sendShell(device, `input keyevent ${input.keyCode}`);
    }
    if (input.type === 'home') {
      return this.sendShell(device, 'input keyevent 3');
    }
    throw new Error('Unsupported input type');
  }

  async screenOn(device) {
    // KEYCODE_WAKEUP 224 often works; then HOME for sane state.
    await this.sendShell(device, 'input keyevent 224').catch(() => null);
    await this.sendShell(device, 'input keyevent 3').catch(() => null);
  }

  async getHealth(device) {
    // Best-effort health probes. Endpoint support differs, so gather what we can.
    const info = { battery: null, mem: null, cpu: null, raw: {} };
    try {
      const battery = await this.sendShell(device, 'dumpsys battery');
      info.raw.battery = battery;
      const m = String(battery).match(/level:\s*(\d+)/i);
      if (m) info.battery = Number(m[1]);
    } catch {}
    try {
      const mem = await this.sendShell(device, 'cat /proc/meminfo | head -n 3');
      info.raw.mem = mem;
      info.mem = String(mem).slice(0, 160);
    } catch {}
    try {
      const cpu = await this.sendShell(device, 'top -n 1 -m 5');
      info.raw.cpu = cpu;
      info.cpu = String(cpu).slice(0, 160);
    } catch {}
    return info;
  }

  async heartbeat(device) {
    try {
      await this.getFrame(device);
      const health = await this.getHealth(device).catch(() => ({ battery: null, mem: null, cpu: null, raw: null }));
      return { online: true, health, error: null };
    } catch (err) {
      return { online: false, health: device.health || null, error: String(err.message || err) };
    }
  }
}

const webkey = new WebkeyAdapter();

// ------------------------------
// Session / queue manager
// ------------------------------
let proDispatchCounter = 0;

function getUserById(id) {
  return db.users.find((u) => u.id === id);
}

function getGameById(id) {
  return CONFIG.GAMES.find((g) => g.id === id);
}

function getDeviceById(id) {
  return db.devices.find((d) => d.id === id);
}

function getSessionById(id) {
  return db.sessions.find((s) => s.id === id);
}

function currentActiveSessionForUser(userId) {
  return db.sessions.find((s) => s.userId === userId && s.status === 'active');
}

function computeSessionDurationMs(user) {
  const minutes = user?.pro ? CONFIG.SESSION_MINUTES_PRO : CONFIG.SESSION_MINUTES_FREE;
  return minutes * 60 * 1000;
}

function sanitizePublicUser(u) {
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    pro: !!u.pro,
    createdAt: u.createdAt,
  };
}

function sanitizePublicSession(s) {
  return {
    id: s.id,
    userId: s.userId,
    gameId: s.gameId,
    gameTitle: s.gameTitle,
    deviceId: s.deviceId,
    status: s.status,
    createdAt: s.createdAt,
    startedAt: s.startedAt,
    endAt: s.endAt,
    endedAt: s.endedAt,
    terminateReason: s.terminateReason || null,
  };
}

function sanitizeAdminDevice(d) {
  return {
    id: d.id,
    name: d.name,
    status: d.status,
    busy: !!d.busy,
    maintenance: !!d.maintenance,
    currentSessionId: d.currentSessionId || null,
    lastSeen: d.lastSeen,
    lastHeartbeatError: d.lastHeartbeatError || null,
    health: d.health || null,
    supportedGames: d.supportedGames || [],
  };
}

function isDeviceAvailableForGame(device, gameId) {
  if (!device) return false;
  if (device.maintenance) return false;
  if (device.status !== 'online') return false;
  if (device.busy) return false;
  if (Array.isArray(device.supportedGames) && device.supportedGames.length > 0) {
    return device.supportedGames.includes(gameId);
  }
  return true;
}

function findAvailableDevice(gameId) {
  return db.devices.find((d) => isDeviceAvailableForGame(d, gameId));
}

async function forceCleanupDeviceForSession(session) {
  const device = getDeviceById(session.deviceId);
  const game = getGameById(session.gameId);
  if (!device) return;
  try {
    if (game) await webkey.stopGame(device, game).catch(() => null);
    await webkey.sendInput(device, { type: 'home' }).catch(() => null);
  } finally {
    device.busy = false;
    device.currentSessionId = null;
  }
}

async function terminateSession(session, reason = 'ended') {
  if (!session || (session.status !== 'active' && session.status !== 'starting')) return;
  session.status = reason === 'timeout' ? 'expired' : 'terminated';
  session.terminateReason = reason;
  session.endedAt = isoNow();
  await forceCleanupDeviceForSession(session);
  db.scheduleSave();
}

async function activateSession(user, gameId, device) {
  const game = getGameById(gameId);
  if (!game) throw new Error('Unknown game');

  const s = {
    id: uid('sess'),
    userId: user.id,
    username: user.username,
    gameId,
    gameTitle: game.title,
    deviceId: device.id,
    status: 'starting',
    createdAt: isoNow(),
    startedAt: null,
    endAt: null,
    endedAt: null,
    terminateReason: null,
  };
  db.sessions.push(s);
  device.busy = true;
  device.currentSessionId = s.id;

  try {
    await webkey.startGame(device, game);
    s.status = 'active';
    s.startedAt = isoNow();
    s.endAt = new Date(now() + computeSessionDurationMs(user)).toISOString();
  } catch (e) {
    s.status = 'failed';
    s.terminateReason = `start_failed: ${String(e.message || e)}`;
    s.endedAt = isoNow();
    device.busy = false;
    device.currentSessionId = null;
    throw e;
  } finally {
    db.scheduleSave();
  }

  return s;
}

function ensureQueueNoDup(userId) {
  db.queue = db.queue.filter((q) => q.userId !== userId);
}

function queuePosition(userId) {
  const idx = db.queue.findIndex((q) => q.userId === userId);
  return idx >= 0 ? idx + 1 : null;
}

function estimateWaitMinutes(position) {
  if (!position) return 0;
  const avg = CONFIG.SESSION_MINUTES_FREE;
  const deviceCount = Math.max(1, db.devices.filter((d) => d.status === 'online' && !d.maintenance).length);
  return Math.ceil(((position - 1) * avg) / deviceCount);
}

function pickNextQueueEntry() {
  if (!db.queue.length) return null;

  const proIdx = db.queue.findIndex((q) => q.pro);
  const normIdx = db.queue.findIndex((q) => !q.pro);

  if (proIdx === -1) return db.queue.shift();
  if (normIdx === -1) return db.queue.splice(proIdx, 1)[0];

  const cycleLen = CONFIG.PRO_PRIORITY_RATIO + 1;
  const slotInCycle = proDispatchCounter % cycleLen;
  proDispatchCounter += 1;

  if (slotInCycle < CONFIG.PRO_PRIORITY_RATIO) {
    return db.queue.splice(proIdx, 1)[0];
  }
  return db.queue.splice(normIdx, 1)[0];
}

async function dispatchQueue() {
  let assigned = false;
  // Try assigning as long as there are free devices and queued users.
  for (;;) {
    if (!db.queue.length) break;
    const entry = pickNextQueueEntry();
    if (!entry) break;
    const user = getUserById(entry.userId);
    if (!user) continue;

    if (currentActiveSessionForUser(user.id)) continue;

    const device = findAvailableDevice(entry.gameId);
    if (!device) {
      // put back if no device for this game currently
      db.queue.push(entry);
      break;
    }

    try {
      await activateSession(user, entry.gameId, device);
      assigned = true;
    } catch (e) {
      console.error('[QUEUE] activateSession failed', e.message || e);
      // Re-queue user for retry.
      db.queue.push({ ...entry, enqueuedAt: isoNow() });
    }
  }

  if (assigned) db.scheduleSave();
}

// ------------------------------
// Express app
// ------------------------------
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// Basic hardening headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

const authSessions = new Map(); // token -> { userId, exp }
const gameTokens = new Map(); // gameToken -> { sessionId, userId, exp }

function requireAuth(req, res, next) {
  const token = getBearer(req);
  if (!token) return res.status(401).json({ error: 'No token' });

  let payload = verifyAuthToken(token);
  if (!payload) {
    // fallback to token store for server-side revocation behavior
    const live = authSessions.get(token);
    if (!live || live.exp < now()) return res.status(401).json({ error: 'Invalid token' });
    payload = { userId: live.userId, role: live.role, exp: live.exp };
  }

  const live = authSessions.get(token);
  if (!live || live.exp < now()) return res.status(401).json({ error: 'Session expired' });

  const user = getUserById(payload.userId);
  if (!user) return res.status(401).json({ error: 'User not found' });

  req.authToken = token;
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

function issueAuth(user) {
  const token = signAuthToken({ userId: user.id, role: user.role }, CONFIG.AUTH_TOKEN_TTL_MS);
  const payload = verifyAuthToken(token);
  authSessions.set(token, { userId: user.id, role: user.role, exp: payload.exp });
  return token;
}

function issueGameToken(session, user) {
  const tok = signAuthToken({ sessionId: session.id, userId: user.id, typ: 'game' }, CONFIG.GAME_TOKEN_TTL_MS);
  const payload = verifyAuthToken(tok);
  gameTokens.set(tok, { sessionId: session.id, userId: user.id, exp: payload.exp });
  return tok;
}

function verifyGameToken(token, sessionId, userId) {
  const live = gameTokens.get(token);
  if (!live || live.exp < now()) return false;
  return live.sessionId === sessionId && live.userId === userId;
}

function revokeUserTokens(userId) {
  for (const [k, v] of authSessions.entries()) {
    if (v.userId === userId) authSessions.delete(k);
  }
  for (const [k, v] of gameTokens.entries()) {
    if (v.userId === userId) gameTokens.delete(k);
  }
}

// ------------------------------
// Public file routes
// ------------------------------
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ------------------------------
// Auth API
// ------------------------------
app.post('/api/register', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!username || !password || password.length < 6) {
    return res.status(400).json({ error: 'username/password invalid (password >= 6)' });
  }
  if (db.users.some((u) => u.username === username)) {
    return res.status(409).json({ error: 'Username already exists' });
  }
  const pw = await createPasswordRecord(password);
  const user = {
    id: uid('user'),
    username,
    password: pw,
    role: 'user',
    pro: false,
    createdAt: isoNow(),
  };
  db.users.push(user);
  db.scheduleSave();
  return res.json({ ok: true, user: sanitizePublicUser(user) });
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.users.find((u) => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await verifyPassword(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = issueAuth(user);
  return res.json({ ok: true, token, user: sanitizePublicUser(user) });
});

app.post('/api/admin/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.users.find((u) => u.username === username && u.role === 'admin');
  if (!user) return res.status(401).json({ error: 'Invalid admin credentials' });
  const ok = await verifyPassword(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid admin credentials' });
  const token = issueAuth(user);
  return res.json({ ok: true, token, user: sanitizePublicUser(user) });
});

app.post('/api/logout', requireAuth, (req, res) => {
  authSessions.delete(req.authToken);
  for (const [k, v] of gameTokens.entries()) {
    if (v.userId === req.user.id) gameTokens.delete(k);
  }
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: sanitizePublicUser(req.user) });
});

app.get('/api/games', requireAuth, (req, res) => {
  res.json({
    games: CONFIG.GAMES.map((g) => ({
      id: g.id,
      title: g.title,
      image: g.image,
      orientation: g.orientation || 'landscape',
    })),
    frameRateDefault: CONFIG.FRAME_RATE_DEFAULT,
  });
});

// ------------------------------
// Queue + session API (user)
// ------------------------------
app.post('/api/queue/join', requireAuth, async (req, res) => {
  const gameId = String(req.body.gameId || '');
  const game = getGameById(gameId);
  if (!game) return res.status(400).json({ error: 'Unknown gameId' });

  const active = currentActiveSessionForUser(req.user.id);
  if (active) {
    const gameToken = issueGameToken(active, req.user);
    return res.json({
      ok: true,
      mode: 'active_session',
      session: sanitizePublicSession(active),
      gameToken,
    });
  }

  const directDevice = findAvailableDevice(gameId);
  if (directDevice) {
    try {
      const session = await activateSession(req.user, gameId, directDevice);
      const gameToken = issueGameToken(session, req.user);
      return res.json({ ok: true, mode: 'assigned', session: sanitizePublicSession(session), gameToken });
    } catch (e) {
      console.error('direct activate failed', e.message || e);
    }
  }

  ensureQueueNoDup(req.user.id);
  db.queue.push({
    id: uid('q'),
    userId: req.user.id,
    username: req.user.username,
    gameId,
    pro: !!req.user.pro,
    enqueuedAt: isoNow(),
  });
  db.scheduleSave();

  const pos = queuePosition(req.user.id);
  res.json({
    ok: true,
    mode: 'queued',
    queue: {
      position: pos,
      etaMinutes: estimateWaitMinutes(pos),
      gameId,
    },
  });
});

app.get('/api/queue/status', requireAuth, (req, res) => {
  const pos = queuePosition(req.user.id);
  const active = currentActiveSessionForUser(req.user.id);
  res.json({
    inQueue: !!pos,
    position: pos,
    etaMinutes: estimateWaitMinutes(pos),
    activeSession: active ? sanitizePublicSession(active) : null,
  });
});

app.get('/api/session/current', requireAuth, (req, res) => {
  const active = currentActiveSessionForUser(req.user.id);
  if (!active) return res.json({ session: null });
  const gameToken = issueGameToken(active, req.user);
  res.json({ session: sanitizePublicSession(active), gameToken });
});

function validateSessionAccess(req, res) {
  const sessionId = req.params.id;
  const s = getSessionById(sessionId);
  if (!s) {
    res.status(404).json({ error: 'Session not found' });
    return null;
  }
  if (s.userId !== req.user.id) {
    res.status(403).json({ error: 'Not your session' });
    return null;
  }
  if (s.status !== 'active') {
    res.status(410).json({ error: 'Session is not active' });
    return null;
  }
  if (new Date(s.endAt).getTime() <= now()) {
    res.status(410).json({ error: 'Session expired' });
    return null;
  }

  const gtok = req.headers['x-game-token'] || req.query.gameToken;
  if (!verifyGameToken(String(gtok || ''), s.id, req.user.id)) {
    res.status(403).json({ error: 'Invalid or expired game token' });
    return null;
  }

  return s;
}

app.get('/api/session/:id/frame', requireAuth, async (req, res) => {
  const s = validateSessionAccess(req, res);
  if (!s) return;

  const device = getDeviceById(s.deviceId);
  if (!device || !device.busy || device.currentSessionId !== s.id) {
    return res.status(409).json({ error: 'Device/session mismatch' });
  }

  try {
    const frame = await webkey.getFrame(device);
    // raw byte proxy; no re-encode.
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', frame.contentType || 'image/jpeg');
    res.send(frame.buffer);
  } catch (e) {
    res.status(502).json({ error: 'Frame proxy failed', detail: String(e.message || e) });
  }
});

app.post('/api/session/:id/input', requireAuth, async (req, res) => {
  const s = validateSessionAccess(req, res);
  if (!s) return;

  const device = getDeviceById(s.deviceId);
  if (!device || !device.busy || device.currentSessionId !== s.id) {
    return res.status(409).json({ error: 'Device/session mismatch' });
  }

  const input = req.body || {};
  const allowedKeyCodes = new Set([19, 20, 21, 22, 23, 24, 25, 62, 66]);

  // Whitelisted input actions only.
  let normalized;
  try {
    if (input.type === 'tap') {
      normalized = {
        type: 'tap',
        x: clamp(Number(input.x || 0), 0, 4000),
        y: clamp(Number(input.y || 0), 0, 4000),
      };
    } else if (input.type === 'swipe') {
      normalized = {
        type: 'swipe',
        x1: clamp(Number(input.x1 || 0), 0, 4000),
        y1: clamp(Number(input.y1 || 0), 0, 4000),
        x2: clamp(Number(input.x2 || 0), 0, 4000),
        y2: clamp(Number(input.y2 || 0), 0, 4000),
        duration: clamp(Number(input.duration || 200), 50, 1200),
      };
    } else if (input.type === 'keyevent') {
      const keyCode = Number(input.keyCode || 0);
      if (!allowedKeyCodes.has(keyCode)) throw new Error('keyCode not allowed');
      normalized = { type: 'keyevent', keyCode };
    } else if (input.type === 'home') {
      normalized = { type: 'home' };
    } else {
      throw new Error('Unsupported input type');
    }
  } catch (e) {
    return res.status(400).json({ error: String(e.message || e) });
  }

  try {
    await webkey.sendInput(device, normalized);
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: 'Input proxy failed', detail: String(e.message || e) });
  }
});

app.post('/api/session/:id/end', requireAuth, async (req, res) => {
  const s = getSessionById(req.params.id);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  if (s.userId !== req.user.id) return res.status(403).json({ error: 'Not your session' });
  await terminateSession(s, 'user_ended');
  await dispatchQueue();
  res.json({ ok: true });
});

// ------------------------------
// Admin API
// ------------------------------
app.get('/api/admin/devices', requireAuth, requireAdmin, (req, res) => {
  res.json({ devices: db.devices.map(sanitizeAdminDevice) });
});

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.json({ users: db.users.map(sanitizePublicUser) });
});

app.get('/api/admin/queue', requireAuth, requireAdmin, (req, res) => {
  res.json({
    queue: db.queue.map((q, idx) => ({
      ...q,
      position: idx + 1,
    })),
  });
});

app.get('/api/admin/sessions', requireAuth, requireAdmin, (req, res) => {
  res.json({ sessions: db.sessions.map(sanitizePublicSession) });
});

app.post('/api/admin/users/:id/pro', requireAuth, requireAdmin, (req, res) => {
  const u = getUserById(req.params.id);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const enable = !!req.body.enable;
  u.pro = enable;
  db.scheduleSave();
  res.json({ ok: true, user: sanitizePublicUser(u) });
});

app.post('/api/admin/sessions/:id/terminate', requireAuth, requireAdmin, async (req, res) => {
  const s = getSessionById(req.params.id);
  if (!s) return res.status(404).json({ error: 'Session not found' });
  await terminateSession(s, 'admin_terminated');
  await dispatchQueue();
  res.json({ ok: true });
});

app.post('/api/admin/devices/:id/action', requireAuth, requireAdmin, async (req, res) => {
  const d = getDeviceById(req.params.id);
  if (!d) return res.status(404).json({ error: 'Device not found' });
  const action = String(req.body.action || '');

  try {
    if (action === 'maintenance_on') {
      d.maintenance = true;
    } else if (action === 'maintenance_off') {
      d.maintenance = false;
    } else if (action === 'refresh') {
      const hb = await webkey.heartbeat(d);
      d.status = hb.online ? 'online' : 'offline';
      d.lastSeen = hb.online ? isoNow() : d.lastSeen;
      d.lastHeartbeatError = hb.error;
      d.health = hb.health;
    } else if (action === 'home') {
      await webkey.sendInput(d, { type: 'home' });
    } else if (action === 'reboot') {
      await webkey.sendShell(d, 'reboot');
    } else if (action === 'screen_off') {
      await webkey.sendShell(d, 'input keyevent 223');
    } else if (action === 'screen_on') {
      await webkey.sendShell(d, 'input keyevent 224');
    } else {
      return res.status(400).json({ error: 'Unknown action' });
    }
    db.scheduleSave();
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// ------------------------------
// Background jobs
// ------------------------------
async function heartbeatLoop() {
  for (const d of db.devices) {
    try {
      const hb = await webkey.heartbeat(d);
      d.status = hb.online ? 'online' : 'offline';
      d.lastSeen = hb.online ? isoNow() : d.lastSeen;
      d.lastHeartbeatError = hb.error;
      if (hb.health) d.health = hb.health;

      if (!hb.online && d.currentSessionId) {
        const s = getSessionById(d.currentSessionId);
        if (s && s.status === 'active') {
          await terminateSession(s, 'device_offline');
        }
      }
    } catch (e) {
      d.status = 'offline';
      d.lastHeartbeatError = String(e.message || e);
    }
  }
  db.scheduleSave();
  await dispatchQueue();
}

async function sessionWatchdog() {
  const t = now();
  let changed = false;
  for (const s of db.sessions) {
    if (s.status === 'active') {
      const endTs = new Date(s.endAt).getTime();
      if (!Number.isFinite(endTs) || endTs <= t) {
        await terminateSession(s, 'timeout');
        changed = true;
      }
    }
  }
  if (changed) {
    db.scheduleSave();
    await dispatchQueue();
  }
}

function startIntervals() {
  setInterval(() => {
    heartbeatLoop().catch((e) => console.error('heartbeatLoop error', e));
  }, CONFIG.HEARTBEAT_INTERVAL_MS);

  setInterval(() => {
    sessionWatchdog().catch((e) => console.error('sessionWatchdog error', e));
  }, CONFIG.SESSION_WATCHDOG_MS);

  // token cleanup
  setInterval(() => {
    const t = now();
    for (const [k, v] of authSessions.entries()) if (v.exp < t) authSessions.delete(k);
    for (const [k, v] of gameTokens.entries()) if (v.exp < t) gameTokens.delete(k);
  }, 60000);
}

// ------------------------------
// Startup
// ------------------------------
async function main() {
  await db.init();
  await heartbeatLoop().catch(() => null);
  await dispatchQueue().catch(() => null);
  startIntervals();

  app.listen(CONFIG.PORT, CONFIG.HOST, () => {
    console.log(`mini GFN server running on http://${CONFIG.HOST}:${CONFIG.PORT}`);
    console.log(`Data dir: ${CONFIG.DATA_DIR}`);
    console.log('Default admin (first run): admin / admin123');
  });
}

main().catch((e) => {
  console.error('Fatal startup error', e);
  process.exit(1);
});
