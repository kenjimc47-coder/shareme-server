'use strict';
// ShareMe browser viewer. No dependencies. All server-provided strings go through textContent (no HTML injection).
(() => {
  const $ = (id) => document.getElementById(id);
  const screens = ['screen-code', 'screen-msg', 'screen-consent'];
  function show(id) {
    for (const s of screens) $(s).hidden = s !== id;
    $('stage').style.display = id === 'stage' ? 'flex' : 'none';
  }
  function message(title, body) {
    $('msg-title').textContent = title;
    $('msg-body').textContent = body || '';
    show('screen-msg');
  }

  // The code lives in the #fragment: browsers never send it to the server in the HTTP request.
  // Strip it from the address bar right away so it isn't left in history or shared by accident.
  let code = decodeURIComponent(location.hash.replace(/^#/, '')).trim();
  if (location.hash) history.replaceState(null, '', location.pathname);

  if (!code) {
    show('screen-code');
    const go = () => {
      const v = $('code-input').value.trim();
      const m = v.match(/#([a-z0-9]+)\s*$/i);
      code = (m ? m[1] : v).toLowerCase();
      if (code) connect();
    };
    $('code-go').onclick = go;
    $('code-input').onkeydown = (e) => { if (e.key === 'Enter') go(); };
  } else {
    connect();
  }

  const REASONS = {
    stopped: 'The sharer stopped sharing.',
    peer_left: 'The sharer left.',
    connection_lost: 'The connection was lost.',
    replaced: 'The sharer started a new share.',
    expired: 'The link expired.',
    declined: 'You declined.',
  };

  function connect() {
    message('Connecting…');
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/media`);
    ws.binaryType = 'arraybuffer';
    let ended = false;
    let watching = false;

    const end = (title, body) => {
      if (ended) return;
      ended = true;
      if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
      message(title, body);
    };

    ws.onopen = () => ws.send(JSON.stringify({ t: 'browser_join', code }));
    ws.onclose = () => end('Share ended', watching ? 'The stream has stopped.' : 'This link is invalid, already used, or expired.');
    ws.onerror = () => {};

    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') { onFrame(ev.data); return; }
      let m;
      try { m = JSON.parse(ev.data); } catch { return; }
      switch (m.t) {
        case 'offer':
          $('consent-from').textContent = String(m.from || 'Someone');
          show('screen-consent');
          $('btn-accept').onclick = () => ws.send(JSON.stringify({ t: 'accept' }));
          $('btn-decline').onclick = () => { ws.send(JSON.stringify({ t: 'decline' })); end('Declined', 'Nothing was shared.'); };
          break;
        case 'media_ok':
          watching = true;
          $('stage-from').textContent = String(m.from || '');
          show('stage');
          break;
        case 'stats':
          sharerStats = m;
          break;
        case 'ended':
          end('Share ended', REASONS[m.reason] || 'The stream has stopped.');
          break;
        case 'error':
          end('Can\'t open this link', m.code === 'rate_limited' ? 'Too many attempts. Wait a minute.' : 'This link is invalid, already used, or expired.');
          break;
      }
    };

    $('btn-stop').onclick = () => { ws.close(1000, 'viewer stopped'); end('Stopped', 'You stopped watching.'); };
    $('btn-full').onclick = () => {
      const el = $('stage');
      if (document.fullscreenElement) document.exitFullscreen(); else el.requestFullscreen().catch(() => {});
    };

    // ---- video
    const canvas = $('canvas');
    const ctx = canvas.getContext('2d', { alpha: false });
    let decoding = false;
    let pending = null; // newest-wins: frames that arrive while decoding replace each other
    let sharerStats = null;
    const frameTimes = [];
    let bytes = 0, bytesStart = performance.now(), kbps = 0;

    function onFrame(buf) {
      if (buf.byteLength <= 20) return;
      const dv = new DataView(buf);
      if (dv.getUint8(0) !== 0x56) return;
      const flags = dv.getUint8(1);
      const seq = dv.getUint32(2);
      const ts = Number(dv.getBigInt64(6));
      // Ack immediately (before decode) so the sharer measures network RTT and can adapt quality.
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: 'ack', seq, ts }));
      bytes += buf.byteLength;
      pending = { buf, paused: (flags & 1) !== 0 };
      if (!decoding) decodeNext();
    }

    async function decodeNext() {
      decoding = true;
      while (pending) {
        const f = pending;
        pending = null;
        try {
          const bmp = await createImageBitmap(new Blob([f.buf.slice(20)], { type: 'image/jpeg' }));
          if (canvas.width !== bmp.width || canvas.height !== bmp.height) {
            canvas.width = bmp.width;
            canvas.height = bmp.height;
          }
          ctx.drawImage(bmp, 0, 0);
          bmp.close();
          $('paused').style.display = f.paused ? 'block' : 'none';
          frameTimes.push(performance.now());
        } catch { /* corrupt frame: skip */ }
      }
      decoding = false;
    }

    setInterval(() => {
      const now = performance.now();
      while (frameTimes.length && now - frameTimes[0] > 2000) frameTimes.shift();
      if (now - bytesStart >= 2000) { kbps = (bytes * 8) / (now - bytesStart); bytes = 0; bytesStart = now; }
      const fps = frameTimes.length / 2;
      const rtt = sharerStats ? ` · rtt ${sharerStats.rtt} ms · q ${sharerStats.q}%` : '';
      $('stats').textContent = `${canvas.width}×${canvas.height} · ${fps.toFixed(0)} fps · ${kbps.toFixed(0)} kbit/s${rtt}`;
    }, 1000);
  }
})();
