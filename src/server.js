'use strict';
/**
 * ShareMe signaling + media relay server.
 *
 *   /ws      signaling (JSON). Mojang-authenticated Minecraft clients: presence, share requests,
 *            accept/decline, session lifecycle, small relayed payloads.
 *   /media   media (binary JPEG frames + small JSON like acks). One socket per role per ACTIVE
 *            session, authenticated with a random single-use token handed out in share_started,
 *            or — for the browser viewer — with a single-use pairing code.
 *   /view    the browser viewer page (code travels in the URL #fragment, never sent to the server
 *            in the HTTP request, so it can't end up in access logs or Referer headers).
 *
 * The server never decodes, stores or inspects video — it forwards opaque frames between exactly
 * two sockets and drops frames when the viewer can't keep up (congestion signal to the sharer).
 *
 * Environment:
 *   PORT                 default 8787
 *   SHAREME_AUTH         "mojang" (default) | "off" (dev only: trusts the claimed name)
 *   REQUEST_TIMEOUT_SEC  default 60 (mod viewer requests)
 *   BROWSER_LINK_SEC     default 300 (browser pairing links)
 *
 * TLS: run behind a reverse proxy (Caddy/nginx/Traefik) that terminates TLS, and point the mod at
 * wss://your-host/ws. Never expose plain ws:// on the public internet.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = parseInt(process.env.PORT || '8787', 10);
const AUTH = (process.env.SHAREME_AUTH || 'mojang').toLowerCase();
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_SEC || '60', 10) * 1000;
const BROWSER_LINK_MS = parseInt(process.env.BROWSER_LINK_SEC || '300', 10) * 1000;
const PROTOCOL_VERSION = 2;
const MAX_TEXT_BYTES = 64 * 1024;
const MAX_FRAME_BYTES = 2 * 1024 * 1024;
const VIEWER_BUFFER_LIMIT = 1536 * 1024; // drop frames when this much is queued to the viewer
const NAME_RE = /^[A-Za-z0-9_]{1,16}$/;
const BROWSER_VIEWER = '#browser'; // not a valid MC name -> can never collide with a player
const CODE_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'; // no 0/o/1/l/i
/** Small JSON messages allowed on /media, forwarded to the other side of the session. */
const MEDIA_TEXT_TYPES = new Set(['ack', 'stats', 'ping', 'react', 'whisper', 'cursor', 'copilot', 'voice_state']);

/** name(lowercase) -> signaling client */
const clients = new Map();
/** sid -> session */
const sessions = new Map();
/** browser pairing code -> sid */
const codes = new Map();

const log = (...a) => console.log(new Date().toISOString(), ...a);
const randomId = (bytes = 16) => crypto.randomBytes(bytes).toString('base64url');
function randomCode(len = 10) {
  const bytes = crypto.randomBytes(len);
  let s = '';
  for (let i = 0; i < len; i++) s += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  return s;
}
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ---------------------------------------------------------------- HTTP: health + browser viewer
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const STATIC = {
  '/view': ['view.html', 'text/html; charset=utf-8'],
  '/view.js': ['view.js', 'text/javascript; charset=utf-8'],
};
const SECURITY_HEADERS = {
  'content-security-policy':
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; " +
    "connect-src 'self' ws: wss:; media-src blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'cache-control': 'no-store',
  'permissions-policy': 'camera=(), geolocation=(), microphone=(self)',
};

const server = http.createServer((req, res) => {
  const url = (req.url || '/').split('?')[0];
  if (url === '/healthz') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
    return;
  }
  const entry = STATIC[url];
  if (entry && req.method === 'GET') {
    fs.readFile(path.join(PUBLIC_DIR, entry[0]), (err, buf) => {
      if (err) {
        res.writeHead(500);
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': entry[1], ...SECURITY_HEADERS });
      res.end(buf);
    });
    return;
  }
  res.writeHead(404, { 'content-type': 'text/plain' });
  res.end('not found');
});

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_TEXT_BYTES });
const mediaWss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES + 64, perMessageDeflate: false });

server.on('upgrade', (req, socket, head) => {
  const url = (req.url || '').split('?')[0];
  const target = url === '/ws' ? wss : url === '/media' ? mediaWss : null;
  if (!target) {
    socket.destroy();
    return;
  }
  target.handleUpgrade(req, socket, head, (ws) => target.emit('connection', ws, req));
});

// ---------------------------------------------------------------- helpers
function send(client, obj) {
  if (client && client.ws.readyState === client.ws.OPEN) client.ws.send(JSON.stringify(obj));
}
function sendWs(ws, obj) {
  if (ws && ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}
function getClient(name) {
  return clients.get(String(name).toLowerCase());
}
function clientIp(req) {
  // Trust X-Forwarded-For only from a local reverse proxy.
  const ra = req.socket.remoteAddress || '';
  const local = ra === '127.0.0.1' || ra === '::1' || ra === '::ffff:127.0.0.1';
  const xff = req.headers['x-forwarded-for'];
  return local && typeof xff === 'string' ? xff.split(',')[0].trim() : ra;
}

/** Simple token bucket: `rate` events per `perMs`. */
function allow(holder, key, rate, perMs) {
  const now = Date.now();
  const b = holder[key] || (holder[key] = { tokens: rate, at: now });
  b.tokens = Math.min(rate, b.tokens + ((now - b.at) / perMs) * rate);
  b.at = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}
const ipBuckets = new Map();
function allowIp(ip, key, rate, perMs) {
  let h = ipBuckets.get(ip);
  if (!h) ipBuckets.set(ip, (h = {}));
  return allow(h, key, rate, perMs);
}
setInterval(() => ipBuckets.clear(), 10 * 60_000).unref();

function newSession(sharer, viewer, kind, timeoutMs) {
  const sid = randomId(16);
  const s = {
    sid, sharer, viewer, kind, state: 'pending', timer: null, tokens: null, code: null,
    media: { sharer: null, viewer: null },
  };
  s.timer = setTimeout(() => endSession(sid, 'expired'), timeoutMs);
  sessions.set(sid, s);
  return s;
}

/**
 * End a session. `actor` (a signaling client) is NOT notified — it already updated itself.
 * Everyone else gets share_ended; media sockets are closed so no more frames can flow.
 */
function endSession(sid, reason, actor) {
  const s = sessions.get(sid);
  if (!s) return;
  sessions.delete(sid);
  clearTimeout(s.timer);
  if (s.code) codes.delete(s.code);
  for (const name of [s.sharer, s.viewer]) {
    const c = getClient(name);
    if (!c) continue;
    if (actor && c === actor) continue;
    send(c, { t: 'share_ended', sid, reason });
  }
  for (const role of ['sharer', 'viewer']) {
    const ws = s.media[role];
    if (!ws) continue;
    sendWs(ws, { t: 'ended', reason });
    try { ws.close(4100, 'session ended'); } catch { /* ignore */ }
  }
  log(`session ${sid.slice(0, 6)} ended (${reason})`);
}

function sessionsOf(client) {
  const out = [];
  for (const s of sessions.values()) {
    if (s.sharer.toLowerCase() === client.key || s.viewer.toLowerCase() === client.key) out.push(s);
  }
  return out;
}

function endOutgoing(conn, reason) {
  for (const s of sessionsOf(conn)) {
    if (s.sharer.toLowerCase() === conn.key) endSession(s.sid, reason, conn);
  }
}

function activate(s) {
  clearTimeout(s.timer);
  s.state = 'active';
  // Random, single-use, per-role tokens for /media. Consumed on first use; die with the session.
  s.tokens = { sharer: randomId(24), viewer: randomId(24) };
  const peerForSharer = s.kind === 'browser' ? 'Browser viewer' : s.viewer;
  send(getClient(s.sharer), { t: 'share_started', sid: s.sid, role: 'sharer', peer: peerForSharer, token: s.tokens.sharer });
  if (s.kind === 'mod') {
    send(getClient(s.viewer), { t: 'share_started', sid: s.sid, role: 'viewer', peer: s.sharer, token: s.tokens.viewer });
  } else {
    s.tokens.viewer = null; // the browser socket is already the viewer media socket
  }
  log(`session ${s.sid.slice(0, 6)} active ${s.sharer} -> ${s.kind === 'browser' ? 'browser' : s.viewer}`);
}

// ---------------------------------------------------------------- Mojang auth
async function verifyMojang(name, serverId) {
  const url = `https://sessionserver.mojang.com/session/minecraft/hasJoined?username=${encodeURIComponent(name)}&serverId=${encodeURIComponent(serverId)}`;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    if (r.status !== 200) return null;
    const j = await r.json();
    return j && j.id && j.name ? j : null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// ================================================================= /ws signaling
wss.on('connection', (ws) => {
  const conn = { ws, name: null, key: null, authed: false, serverId: randomId(15), buckets: {} };
  const authTimer = setTimeout(() => { if (!conn.authed) ws.close(4001, 'auth timeout'); }, 10_000);
  send(conn, { t: 'challenge', serverId: conn.serverId });

  ws.on('message', async (data, isBinary) => {
    if (isBinary) return;
    if (!allow(conn.buckets, 'msg', 60, 1000)) return;
    let m;
    try { m = JSON.parse(data.toString('utf8')); } catch { return; }
    if (!m || typeof m.t !== 'string') return;
    if (!conn.authed) {
      if (m.t !== 'hello') return;
      await handleHello(conn, m);
      if (conn.authed) clearTimeout(authTimer);
      return;
    }
    try { handle(conn, m); } catch (e) { log('handler error', e); }
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    if (!conn.authed) return;
    for (const s of sessionsOf(conn)) endSession(s.sid, 'peer_left', conn);
    if (clients.get(conn.key) === conn) clients.delete(conn.key);
    log(`- ${conn.name} (${clients.size} online)`);
  });
});

async function handleHello(conn, m) {
  if (m.version !== PROTOCOL_VERSION) {
    send(conn, { t: 'error', code: 'bad_version' });
    conn.ws.close(4002, 'bad version');
    return;
  }
  if (typeof m.name !== 'string' || !NAME_RE.test(m.name)) {
    conn.ws.close(4003, 'bad name');
    return;
  }
  let name = m.name;
  if (AUTH !== 'off') {
    const profile = await verifyMojang(m.name, conn.serverId);
    if (!profile) {
      send(conn, { t: 'error', code: 'auth_failed' });
      conn.ws.close(4004, 'auth failed');
      return;
    }
    name = profile.name;
  }
  if (conn.ws.readyState !== conn.ws.OPEN) return;
  conn.name = name;
  conn.key = name.toLowerCase();
  conn.authed = true;
  const old = clients.get(conn.key);
  if (old && old !== conn) {
    send(old, { t: 'error', code: 'replaced_login' });
    old.ws.close(4005, 'replaced');
    for (const s of sessionsOf(old)) endSession(s.sid, 'peer_left', old);
  }
  clients.set(conn.key, conn);
  send(conn, { t: 'welcome', name });
  log(`+ ${name} (${clients.size} online, auth=${AUTH})`);
}

function handle(conn, m) {
  switch (m.t) {
    case 'query': {
      if (!Array.isArray(m.names) || !allow(conn.buckets, 'query', 2, 1000)) return;
      const online = m.names.slice(0, 500)
        .filter((n) => typeof n === 'string' && NAME_RE.test(n))
        .map((n) => getClient(n))
        .filter((c) => c && c !== conn)
        .map((c) => c.name);
      send(conn, { t: 'presence', online });
      return;
    }

    case 'share_request': {
      if (typeof m.to !== 'string' || !NAME_RE.test(m.to)) return send(conn, { t: 'error', code: 'bad_request' });
      if (!allow(conn.buckets, 'request', 3, 10_000)) return send(conn, { t: 'error', code: 'rate_limited' });
      const target = getClient(m.to);
      if (!target || target === conn) return send(conn, { t: 'error', code: 'peer_offline' });
      endOutgoing(conn, 'replaced'); // one viewer per sharer
      const s = newSession(conn.name, target.name, 'mod', REQUEST_TIMEOUT_MS);
      // share_pending always reaches the sharer before any share_ended for this sid.
      send(conn, { t: 'share_pending', sid: s.sid, to: target.name });
      send(target, { t: 'share_offer', sid: s.sid, from: conn.name });
      log(`session ${s.sid.slice(0, 6)} offered ${conn.name} -> ${target.name}`);
      return;
    }

    case 'browser_share': {
      if (!allow(conn.buckets, 'request', 3, 10_000)) return send(conn, { t: 'error', code: 'rate_limited' });
      endOutgoing(conn, 'replaced');
      const s = newSession(conn.name, BROWSER_VIEWER, 'browser', BROWSER_LINK_MS);
      s.code = randomCode(10);
      codes.set(s.code, s.sid);
      send(conn, { t: 'share_pending', sid: s.sid, to: 'Browser viewer' });
      send(conn, { t: 'browser_link', sid: s.sid, code: s.code, expiresSec: Math.round(BROWSER_LINK_MS / 1000) });
      log(`session ${s.sid.slice(0, 6)} browser link created by ${conn.name}`);
      return;
    }

    case 'share_cancel': {
      for (const s of sessionsOf(conn)) {
        if (s.sharer.toLowerCase() === conn.key && s.state === 'pending') endSession(s.sid, 'cancelled', conn);
      }
      return;
    }

    case 'share_answer': {
      const s = sessions.get(m.sid);
      if (!s || s.kind !== 'mod' || s.state !== 'pending' || s.viewer.toLowerCase() !== conn.key) return;
      if (m.accept !== true) return endSession(s.sid, 'declined', conn);
      if (!getClient(s.sharer)) return endSession(s.sid, 'peer_left');
      for (const other of sessionsOf(conn)) {
        if (other.sid !== s.sid && other.state === 'active' && other.viewer.toLowerCase() === conn.key) {
          endSession(other.sid, 'replaced', conn);
        }
      }
      activate(s);
      return;
    }

    case 'share_stop': {
      const s = sessions.get(m.sid);
      if (!s) return;
      if (s.sharer.toLowerCase() !== conn.key && s.viewer.toLowerCase() !== conn.key) return;
      endSession(s.sid, s.state === 'pending' ? 'cancelled' : 'stopped', conn);
      return;
    }

    case 'relay': {
      const s = sessions.get(m.sid);
      if (!s || s.state !== 'active' || s.kind !== 'mod') return;
      if (!allow(conn.buckets, 'relay', 30, 1000)) return;
      const isSharer = s.sharer.toLowerCase() === conn.key;
      const isViewer = s.viewer.toLowerCase() === conn.key;
      if (!isSharer && !isViewer) return;
      send(getClient(isSharer ? s.viewer : s.sharer), { t: 'relay', sid: s.sid, from: conn.name, data: m.data });
      return;
    }

    default:
      return;
  }
}

// ================================================================= /media
mediaWss.on('connection', (ws, req) => {
  const ip = clientIp(req);
  const m = { ws, sid: null, role: null, authed: false, browserPending: false, buckets: {}, lastCongestion: 0 };
  const authTimer = setTimeout(() => { if (!m.authed && !m.browserPending) ws.close(4001, 'auth timeout'); }, 8000);

  ws.on('message', (data, isBinary) => {
    if (!m.authed) {
      if (isBinary || data.length > 1024) return ws.close(4003, 'bad auth');
      let msg;
      try { msg = JSON.parse(data.toString('utf8')); } catch { return ws.close(4003, 'bad auth'); }
      handleMediaAuth(m, msg, ip);
      return;
    }
    const s = sessions.get(m.sid);
    if (!s || s.state !== 'active') return;

    if (isBinary) {
      // Video frames: sharer -> viewer only. Opaque bytes; we never parse the image.
      if (m.role !== 'sharer' || data.length > MAX_FRAME_BYTES) return;
      const v = s.media.viewer;
      if (!v || v.readyState !== v.OPEN) return;
      if (v.bufferedAmount > VIEWER_BUFFER_LIMIT) {
        // Viewer can't keep up: drop this frame and tell the sharer (at most 4x/s) so it lowers bitrate.
        const now = Date.now();
        if (now - m.lastCongestion > 250) {
          m.lastCongestion = now;
          sendWs(ws, { t: 'congestion', buffered: v.bufferedAmount });
        }
        return;
      }
      v.send(data, { binary: true });
      return;
    }

    if (data.length > 2048 || !allow(m.buckets, 'text', 60, 1000)) return;
    let msg;
    try { msg = JSON.parse(data.toString('utf8')); } catch { return; }
    if (!msg || !MEDIA_TEXT_TYPES.has(msg.t)) return;
    const other = s.media[m.role === 'sharer' ? 'viewer' : 'sharer'];
    sendWs(other, msg);
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    if (!m.sid) return;
    const s = sessions.get(m.sid);
    if (!s || s.media[m.role] !== ws) return;
    s.media[m.role] = null;
    // Fail closed: losing a media socket ends the share (a closed browser tab = viewer left).
    endSession(s.sid, s.state === 'pending' ? 'declined' : (s.kind === 'browser' && m.role === 'viewer' ? 'peer_left' : 'connection_lost'));
  });
});

function handleMediaAuth(m, msg, ip) {
  const ws = m.ws;
  if (!msg || typeof msg.t !== 'string') return ws.close(4003, 'bad auth');

  // --- Mod clients: {t:'media_auth', sid, role, token}
  if (msg.t === 'media_auth') {
    const s = sessions.get(msg.sid);
    const role = msg.role === 'sharer' ? 'sharer' : msg.role === 'viewer' ? 'viewer' : null;
    if (!s || s.state !== 'active' || !role || !s.tokens || !safeEqual(msg.token, s.tokens[role]) || s.media[role]) {
      sendWs(ws, { t: 'error', code: 'bad_token' });
      return ws.close(4003, 'bad token');
    }
    s.tokens[role] = null; // single use
    s.media[role] = ws;
    m.sid = s.sid;
    m.role = role;
    m.authed = true;
    sendWs(ws, { t: 'media_ok', role });
    return;
  }

  // --- Browser viewer step 1: {t:'browser_join', code}
  if (msg.t === 'browser_join') {
    if (!allowIp(ip, 'join', 10, 60_000)) {
      sendWs(ws, { t: 'error', code: 'rate_limited' });
      return ws.close(4029, 'rate limited');
    }
    const code = typeof msg.code === 'string' ? msg.code.toLowerCase() : '';
    const sid = codes.get(code);
    const s = sid && sessions.get(sid);
    if (!s || s.kind !== 'browser' || s.state !== 'pending' || s.media.viewer) {
      sendWs(ws, { t: 'error', code: 'invalid_link' });
      return ws.close(4004, 'invalid link');
    }
    codes.delete(code); // single use: nobody else can open this link now
    s.code = null;
    s.media.viewer = ws;
    m.sid = s.sid;
    m.role = 'viewer';
    m.browserPending = true;
    sendWs(ws, { t: 'offer', from: s.sharer });
    return;
  }

  // --- Browser viewer step 2: explicit consent
  if ((msg.t === 'accept' || msg.t === 'decline') && m.browserPending) {
    const s = sessions.get(m.sid);
    if (!s || s.state !== 'pending') return ws.close(4004, 'gone');
    m.browserPending = false;
    if (msg.t === 'decline') {
      s.media.viewer = null;
      endSession(s.sid, 'declined');
      return ws.close(1000, 'declined');
    }
    m.authed = true;
    activate(s);
    sendWs(ws, { t: 'media_ok', role: 'viewer', from: s.sharer });
    return;
  }

  ws.close(4003, 'bad auth');
}

// Heartbeat on both endpoints: drop dead connections within ~40s so shares end when a game crashes.
function heartbeat(server) {
  server.on('connection', (ws) => {
    ws._alive = true;
    ws.on('pong', () => { ws._alive = true; });
  });
  setInterval(() => {
    for (const ws of server.clients) {
      if (ws._alive === false) { ws.terminate(); continue; }
      ws._alive = false;
      ws.ping();
    }
  }, 20_000).unref();
}
heartbeat(wss);
heartbeat(mediaWss);

server.listen(PORT, () => {
  log(`ShareMe server listening on :${PORT} (signaling /ws, media /media, viewer /view, auth=${AUTH})`);
  if (AUTH === 'off') log('WARNING: SHAREME_AUTH=off — anyone can claim any name. Dev use only.');
});
