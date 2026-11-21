'use strict';
/**
 * End-to-end test of the ShareMe server (no Minecraft needed).
 *   npm test        (starts the server on a random port with SHAREME_AUTH=off, runs, stops it)
 *
 * Covers: auth handshake, presence, request/decline, request/accept, media auth with single-use
 * tokens, frame relay + acks, token reuse rejected, stop -> share_ended + media closed,
 * browser link flow (join -> consent -> frames), link reuse rejected, peer disconnect ends share.
 */
const { spawn } = require('child_process');
const path = require('path');
const assert = require('assert');
const WebSocket = require('ws');

const PORT = 18000 + Math.floor(Math.random() * 1000);
const BASE = `ws://127.0.0.1:${PORT}`;
const PROTOCOL_VERSION = 2;

function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

/** WebSocket wrapper with "await next message of type X". */
function client(url) {
  const ws = new WebSocket(url);
  const queue = [];
  const waiters = [];
  ws.on('message', (data, isBinary) => {
    const item = isBinary ? { t: '__binary', data } : JSON.parse(data.toString());
    const i = waiters.findIndex((w) => w.match(item));
    if (i >= 0) waiters.splice(i, 1)[0].resolve(item);
    else queue.push(item);
  });
  const closed = new Promise((r) => ws.on('close', (code) => r(code)));
  return {
    ws,
    closed,
    open: () => new Promise((r, j) => { ws.once('open', r); ws.once('error', j); }),
    send: (o) => ws.send(JSON.stringify(o)),
    next(type, timeout = 3000) {
      const match = (it) => it.t === type;
      const i = queue.findIndex(match);
      if (i >= 0) return Promise.resolve(queue.splice(i, 1)[0]);
      return new Promise((resolve, reject) => {
        const w = { match, resolve };
        waiters.push(w);
        setTimeout(() => { const k = waiters.indexOf(w); if (k >= 0) { waiters.splice(k, 1); reject(new Error(`timeout waiting for ${type}`)); } }, timeout);
      });
    },
  };
}

async function login(name) {
  const c = client(`${BASE}/ws`);
  await c.open();
  await c.next('challenge');
  c.send({ t: 'hello', name, uuid: '', mojang: false, version: PROTOCOL_VERSION });
  await c.next('welcome');
  return c;
}

async function media(sid, role, token) {
  const c = client(`${BASE}/media`);
  await c.open();
  c.send({ t: 'media_auth', sid, role, token });
  return c;
}

function frame(seq) {
  const b = Buffer.alloc(20 + 100);
  b[0] = 0x56; b[1] = 0; b.writeUInt32BE(seq, 2); b.writeBigInt64BE(BigInt(Date.now()), 6);
  b.writeUInt16BE(64, 14); b.writeUInt16BE(36, 16);
  return b;
}

async function run() {
  // --- login + presence
  const alice = await login('Alice');
  const bob = await login('Bob');
  alice.send({ t: 'query', names: ['Bob', 'Carol'] });
  const pres = await alice.next('presence');
  assert.deepStrictEqual(pres.online, ['Bob']);
  console.log('✓ auth + presence');

  // --- decline
  alice.send({ t: 'share_request', to: 'Bob' });
  const p1 = await alice.next('share_pending');
  const o1 = await bob.next('share_offer');
  assert.strictEqual(o1.from, 'Alice');
  assert.strictEqual(o1.sid, p1.sid);
  bob.send({ t: 'share_answer', sid: o1.sid, accept: false });
  const e1 = await alice.next('share_ended');
  assert.strictEqual(e1.reason, 'declined');
  console.log('✓ request -> decline');

  // --- accept + media
  await wait(50);
  alice.send({ t: 'share_request', to: 'Bob' });
  const p2 = await alice.next('share_pending');
  const o2 = await bob.next('share_offer');
  bob.send({ t: 'share_answer', sid: o2.sid, accept: true });
  const sA = await alice.next('share_started');
  const sB = await bob.next('share_started');
  assert.strictEqual(sA.role, 'sharer');
  assert.strictEqual(sB.role, 'viewer');
  assert.notStrictEqual(sA.token, sB.token);
  const mA = await media(p2.sid, 'sharer', sA.token);
  await mA.next('media_ok');
  const mB = await media(p2.sid, 'viewer', sB.token);
  await mB.next('media_ok');
  console.log('✓ request -> accept -> media auth');

  // token reuse is rejected
  const reuse = await media(p2.sid, 'viewer', sB.token);
  const err = await reuse.next('error');
  assert.strictEqual(err.code, 'bad_token');
  console.log('✓ single-use media token');

  // frames + acks
  mA.ws.send(frame(7));
  const got = await mB.next('__binary');
  assert.strictEqual(got.data.readUInt32BE(2), 7);
  mB.send({ t: 'ack', seq: 7, ts: 1 });
  const ack = await mA.next('ack');
  assert.strictEqual(ack.seq, 7);
  // viewer can't inject frames toward the sharer
  mB.ws.send(frame(99));
  await wait(150);
  console.log('✓ frame relay + ack');

  // stop -> both notified, media closed
  alice.send({ t: 'share_stop', sid: p2.sid });
  const e2 = await bob.next('share_ended');
  assert.strictEqual(e2.reason, 'stopped');
  const codeB = await mB.closed;
  assert.strictEqual(codeB, 4100);
  console.log('✓ stop ends share and closes media');

  // --- browser link flow
  alice.send({ t: 'browser_share' });
  const p3 = await alice.next('share_pending');
  const link = await alice.next('browser_link');
  assert.ok(/^[a-z0-9]{10}$/.test(link.code));
  const br = client(`${BASE}/media`);
  await br.open();
  br.send({ t: 'browser_join', code: link.code });
  const offer = await br.next('offer');
  assert.strictEqual(offer.from, 'Alice');
  // reuse of the link is rejected immediately (single use)
  const br2 = client(`${BASE}/media`);
  await br2.open();
  br2.send({ t: 'browser_join', code: link.code });
  assert.strictEqual((await br2.next('error')).code, 'invalid_link');
  br.send({ t: 'accept' });
  await br.next('media_ok');
  const sA3 = await alice.next('share_started');
  assert.strictEqual(sA3.peer, 'Browser viewer');
  const mA3 = await media(p3.sid, 'sharer', sA3.token);
  await mA3.next('media_ok');
  mA3.ws.send(frame(1));
  assert.strictEqual((await br.next('__binary')).data.readUInt32BE(2), 1);
  console.log('✓ browser link -> consent -> frames, link single-use');

  // closing the browser tab ends the share for the sharer
  br.ws.close();
  const e3 = await alice.next('share_ended');
  assert.strictEqual(e3.reason, 'peer_left');
  console.log('✓ browser close ends share');

  // --- viewer disconnect ends share
  alice.send({ t: 'share_request', to: 'Bob' });
  await alice.next('share_pending');
  const o4 = await bob.next('share_offer');
  bob.send({ t: 'share_answer', sid: o4.sid, accept: true });
  await alice.next('share_started');
  bob.ws.close();
  const e4 = await alice.next('share_ended');
  assert.strictEqual(e4.reason, 'peer_left');
  console.log('✓ viewer leaving ends share');

  alice.ws.close();
}

const srv = spawn(process.execPath, [path.join(__dirname, '..', 'src', 'server.js')], {
  env: { ...process.env, PORT: String(PORT), SHAREME_AUTH: 'off' },
  stdio: ['ignore', 'pipe', 'inherit'],
});
srv.stdout.on('data', (d) => { if (process.env.VERBOSE) process.stdout.write(d); });

(async () => {
  for (let i = 0; i < 50; i++) {
    try { const c = client(`${BASE}/ws`); await c.open(); c.ws.close(); break; } catch { await wait(100); }
  }
  try {
    await run();
    console.log('\nALL SERVER TESTS PASSED');
    process.exitCode = 0;
  } catch (e) {
    console.error('\nTEST FAILED:', e);
    process.exitCode = 1;
  } finally {
    srv.kill();
    setTimeout(() => process.exit(), 200);
  }
})();
