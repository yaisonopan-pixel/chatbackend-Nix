'use strict';
// Nix server: serves the site, handles accounts (cookie sessions) and a moderated global chat.
// No dependencies. Run: node server.js   (Node 18+)
const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path'), { promisify } = require('util');
const scrypt = promisify(crypto.scrypt), E = process.env;
const PORT = process.env.PORT || +E.PORT || 3000, PROD = E.NODE_ENV === 'production';
const list = s => (s || '').split(',').map(x => x.trim()).filter(Boolean);
const ADMINS = list(E.ADMINS).map(x => x.toLowerCase());       // usernames that can moderate
const ORIGINS = list(E.ALLOWED_ORIGINS);                         // extra origins allowed to call the API
const FILE = E.DATA_FILE || path.join(__dirname, 'data.json');
const BLOCK = ['fuck', 'shit', 'bitch', 'cunt', 'nigg', 'fag', 'porn', 'whore', ...list(E.BLOCKED_WORDS).map(x => x.toLowerCase())];
const LINK = /(https?:|www\.|\b[\w-]+\.(com|net|org|io|gg|xyz|lol|me|tv|co)\b|[\w.+-]+@[\w-]+\.\w+|\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b)/i;

/* ---------- storage (JSON file, flushed every 2s) ---------- */
let DB = { users: {}, sessions: {}, msgs: [], reports: [], nextId: 1 }, dirty = false;
try { DB = { ...DB, ...JSON.parse(fs.readFileSync(FILE, 'utf8')) }; } catch { }
const touch = () => { dirty = true; };
function flush() { if (!dirty) return; dirty = false; fs.writeFileSync(FILE + '.tmp', JSON.stringify(DB)); fs.renameSync(FILE + '.tmp', FILE); }
setInterval(flush, 2000);
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => { flush(); process.exit(0); });

/* ---------- helpers ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const leet = s => s.toLowerCase().replace(/[0@]/g, 'o').replace(/[1!|]/g, 'i').replace(/3/g, 'e').replace(/4/g, 'a').replace(/[5$]/g, 's').replace(/[^a-z]/g, '');
const rude = s => BLOCK.some(w => leet(s).includes(w));
const isAdmin = u => ADMINS.includes(u.name.toLowerCase());
const pub = u => ({ name: u.name, admin: isAdmin(u) });
const cookies = h => Object.fromEntries((h || '').split(';').map(c => { const i = c.indexOf('='); return i < 0 ? [''] : [c.slice(0, i).trim(), c.slice(i + 1).trim()]; }).filter(x => x[0]));
const ip = req => (PROD && E.TRUST_PROXY ? String(req.headers['x-forwarded-for'] || '').split(',').pop().trim() : '') || req.socket.remoteAddress;
function sessionUser(req) {
  const t = cookies(req.headers.cookie).nix_sid; if (!t) return null;
  const s = DB.sessions[sha(t)]; if (!s || s.exp < Date.now()) return null;
  const u = DB.users[s.u]; return u && !u.banned ? u : null;
}
function originOk(req) {
  const o = req.headers.origin; if (!o) return true;
  try { return new URL(o).host === req.headers.host || ORIGINS.includes(o); } catch { return false; }
}
const hits = new Map();
function limited(key, max, ms) { const n = Date.now(), a = (hits.get(key) || []).filter(t => n - t < ms); a.push(n); hits.set(key, a); return a.length > max; }
setInterval(() => { const n = Date.now(); for (const [k, a] of hits) if (!a.some(t => n - t < 3600e3)) hits.delete(k); }, 600e3);
// Cookie is HttpOnly (JS can't read it). In production it is Secure + SameSite=None + Partitioned so it still
// works when the site is embedded in an iframe (e.g. Google Sites); the Origin check above replaces SameSite as CSRF defence.
const ck = (tok, age) => `nix_sid=${tok}; Path=/; HttpOnly; Max-Age=${age}` + (PROD ? '; Secure; SameSite=None; Partitioned' : '; SameSite=Lax');
function readJSON(req) {
  return new Promise((ok, no) => { let b = ''; req.on('data', d => { b += d; if (b.length > 2048) { no(new Error('big')); req.destroy(); } }); req.on('end', () => { try { ok(JSON.parse(b || '{}')); } catch { no(new Error('bad json')); } }); });
}
async function check(u, pw) {
  const h = await scrypt(String(pw), u ? u.salt : '0'.repeat(32), 64);
  return !!u && crypto.timingSafeEqual(h, Buffer.from(u.h, 'hex'));
}

/* ---------- HTTP ---------- */
const server = http.createServer(async (req, res) => {
  const send = (c, o, h = {}) => { res.writeHead(c, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...h }); res.end(JSON.stringify(o)); };
  try {
    const url = req.url.split('?')[0], me = ip(req);
    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
      return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
    }
    if (!url.startsWith('/api/')) return send(404, { error: 'Not found' });
    if (req.method === 'GET' && url === '/api/me') { const u = sessionUser(req); return send(200, { user: u ? pub(u) : null }); }
    if (req.method !== 'POST') return send(405, { error: 'Method not allowed' });
    if (!originOk(req)) return send(403, { error: 'Bad origin' });
    const b = await readJSON(req), start = (k, u) => {
      const tok = crypto.randomBytes(32).toString('hex');
      for (const [h, s] of Object.entries(DB.sessions)) if (s.exp < Date.now()) delete DB.sessions[h];
      DB.sessions[sha(tok)] = { u: k, exp: Date.now() + 30 * 864e5 }; touch();
      send(200, { user: pub(u) }, { 'Set-Cookie': ck(tok, 30 * 86400) });
    };
    if (url === '/api/signup') {
      if (limited('su' + me, 5, 3600e3)) return send(429, { error: 'Too many sign-ups from this network. Try again later.' });
      const name = String(b.username || ''), pw = String(b.password || ''), k = name.toLowerCase();
      if (!/^[A-Za-z0-9_]{3,16}$/.test(name)) return send(400, { error: 'Username: 3-16 letters, numbers or _' });
      if (rude(name) || (/^(admin|mod|system|nix)/i.test(name) && !ADMINS.includes(k))) return send(400, { error: 'That username is not available' });
      if (pw.length < 8 || pw.length > 100) return send(400, { error: 'Password must be 8-100 characters' });
      const salt = crypto.randomBytes(16).toString('hex'), h = (await scrypt(pw, salt, 64)).toString('hex');
      if (DB.users[k]) return send(409, { error: 'That username is taken' });
      DB.users[k] = { name, salt, h, created: Date.now() }; touch();
      return start(k, DB.users[k]);
    }
    if (url === '/api/login') {
      if (limited('li' + me, 10, 600e3)) return send(429, { error: 'Too many attempts. Wait a few minutes.' });
      const k = String(b.username || '').toLowerCase(), u = DB.users[k];
      if (!(await check(u, b.password)) || u.banned) return send(401, { error: 'Wrong username or password' });
      return start(k, u);
    }
    if (url === '/api/logout') {
      const t = cookies(req.headers.cookie).nix_sid; if (t) { delete DB.sessions[sha(t)]; touch(); }
      return send(200, { ok: true }, { 'Set-Cookie': ck('', 0) });
    }
    if (url === '/api/delete') {
      const u = sessionUser(req); if (!u) return send(401, { error: 'Not signed in' });
      if (!(await check(u, b.password))) return send(401, { error: 'Wrong password' });
      const k = u.name.toLowerCase();
      for (const [h, s] of Object.entries(DB.sessions)) if (s.u === k) delete DB.sessions[h];
      for (const m of DB.msgs.filter(m => m.k === k)) bcast({ t: 'del', id: m.id });
      DB.msgs = DB.msgs.filter(m => m.k !== k); delete DB.users[k]; touch();
      for (const c of clients) if (c.k === k) c.sock.destroy();
      return send(200, { ok: true }, { 'Set-Cookie': ck('', 0) });
    }
    send(404, { error: 'Not found' });
  } catch (e) { send(400, { error: 'Bad request' }); }
});

/* ---------- WebSocket chat (RFC 6455, text frames only) ---------- */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', clients = new Set();
function frame(op, data) {
  const p = Buffer.from(data), n = p.length; let h;
  if (n < 126) h = Buffer.from([0x80 | op, n]); else if (n < 65536) h = Buffer.from([0x80 | op, 126, n >> 8, n & 255]);
  else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
  return Buffer.concat([h, p]);
}
const wsend = (c, o) => { if (!c.sock.destroyed) c.sock.write(frame(1, JSON.stringify(o))); };
const bcast = o => { const f = frame(1, JSON.stringify(o)); for (const c of clients) if (!c.sock.destroyed) c.sock.write(f); };
const online = () => bcast({ t: 'online', n: new Set([...clients].map(c => c.k)).size });
const pm = m => ({ id: m.id, u: m.u, ts: m.ts, x: m.x });

server.on('upgrade', (req, sock) => {
  const u = req.url.split('?')[0] === '/ws' && originOk(req) && sessionUser(req), key = req.headers['sec-websocket-key'];
  if (!u || !key || limited('ws' + ip(req), 30, 60e3)) return sock.end('HTTP/1.1 403 Forbidden\r\n\r\n');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + crypto.createHash('sha1').update(key + GUID).digest('base64') + '\r\n\r\n');
  const c = { sock, k: u.name.toLowerCase(), name: u.name, buf: Buffer.alloc(0), last: 0, alive: true };
  clients.add(c);
  wsend(c, { t: 'hist', msgs: DB.msgs.slice(-50).map(pm), online: new Set([...clients].map(x => x.k)).size });
  online();
  const gone = () => { if (clients.delete(c)) online(); };
  sock.on('close', gone); sock.on('error', () => sock.destroy());
  sock.on('data', d => {
    c.buf = Buffer.concat([c.buf, d]); if (c.buf.length > 8192) return sock.destroy();
    for (; ;) {
      const b = c.buf; if (b.length < 2) break;
      const fin = b[0] & 128, op = b[0] & 15, masked = b[1] & 128; let n = b[1] & 127, o = 2;
      if (n === 126) { if (b.length < 4) break; n = b.readUInt16BE(2); o = 4; } else if (n === 127) { if (b.length < 10) break; n = Number(b.readBigUInt64BE(2)); o = 10; }
      if (!masked || !fin || n > 2048) return sock.destroy();
      if (b.length < o + 4 + n) break;
      const m = b.subarray(o, o + 4), p = Buffer.from(b.subarray(o + 4, o + 4 + n)); for (let i = 0; i < n; i++) p[i] ^= m[i & 3];
      c.buf = b.subarray(o + 4 + n);
      if (op === 8) { sock.end(frame(8, '')); return; }
      else if (op === 9) sock.write(frame(10, p));
      else if (op === 10) c.alive = true;
      else if (op === 1) onMsg(c, p.toString('utf8'));
      else return sock.destroy();
    }
  });
});
setInterval(() => { for (const c of clients) { if (!c.alive) { c.sock.destroy(); continue; } c.alive = false; c.sock.write(frame(9, '')); } }, 30000);

function onMsg(c, raw) {
  let d; try { d = JSON.parse(raw); } catch { return; }
  const u = DB.users[c.k]; if (!u || u.banned) return c.sock.destroy();
  const err = m => wsend(c, { t: 'err', m });
  if (d.t === 'report') {
    const m = DB.msgs.find(x => x.id === d.id); if (!m || limited('rp' + c.k, 5, 60e3)) return;
    DB.reports.push({ id: m.id, u: m.u, x: m.x, by: c.name, ts: Date.now() }); DB.reports = DB.reports.slice(-100); touch();
    console.log('REPORT', m.id, m.u, JSON.stringify(m.x), 'by', c.name); return wsend(c, { t: 'sys', m: 'Thanks, the message was reported to the moderators.' });
  }
  if (d.t !== 'msg') return;
  const text = String(d.x || '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim(), n = Date.now();
  if (!text) return;
  if (text[0] === '/') return command(c, u, text, err);
  if (u.mutedUntil > n) return err('You are muted for ' + Math.ceil((u.mutedUntil - n) / 60000) + ' more minute(s).');
  if (n - c.last < 1200 || limited('m' + c.k, 20, 60e3)) return err('Slow down a little.');
  if (text.length > 300) return err('Messages can be up to 300 characters.');
  if (LINK.test(text)) return err('Links and contact info are not allowed in chat.');
  if (rude(text)) return err('Please keep it friendly.');
  c.last = n; const m = { id: DB.nextId++, u: u.name, k: c.k, ts: n, x: text };
  DB.msgs.push(m); if (DB.msgs.length > 200) DB.msgs.shift(); touch(); bcast({ t: 'msg', m: pm(m) });
}
function command(c, u, text, err) {
  if (!isAdmin(u)) return err('Unknown command.');
  const [cmd, a, b] = text.slice(1).split(' '), target = DB.users[String(a || '').toLowerCase()], sys = m => wsend(c, { t: 'sys', m });
  if (cmd === 'del') { const id = +a; if (!DB.msgs.some(m => m.id === id)) return err('No such message.'); DB.msgs = DB.msgs.filter(m => m.id !== id); touch(); return bcast({ t: 'del', id }); }
  if (cmd === 'mute' && target) { target.mutedUntil = Date.now() + (+b || 10) * 60000; touch(); return sys(target.name + ' muted for ' + (+b || 10) + ' min.'); }
  if (cmd === 'unmute' && target) { target.mutedUntil = 0; touch(); return sys(target.name + ' unmuted.'); }
  if (cmd === 'ban' && target) {
    target.banned = true; const k = target.name.toLowerCase(); touch();
    for (const [h, s] of Object.entries(DB.sessions)) if (s.u === k) delete DB.sessions[h];
    for (const x of clients) if (x.k === k) x.sock.destroy(); return sys(target.name + ' banned.');
  }
  if (cmd === 'reports') return sys(DB.reports.slice(-5).map(r => `#${r.id} ${r.u}: "${r.x}" (by ${r.by})`).join(' | ') || 'No reports.');
  err('Commands: /del id, /mute name [min], /unmute name, /ban name, /reports');
}

server.listen(PORT, () => console.log('Nix running on http://localhost:' + PORT + (ADMINS.length ? ' (admins: ' + ADMINS.join(', ') + ')' : ' (set ADMINS=yourname to enable moderation)')));
