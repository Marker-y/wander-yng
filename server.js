'use strict';
// Musical Beats - backend (zero external deps, Node built-ins only)
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── storage helpers ──
function load(file, def) {
  const p = path.join(DATA_DIR, file);
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return def; }
}
function save(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2));
}
let users = load('users.json', []);
let sessions = load('sessions.json', {});
let charts = load('charts.json', []);
let requests = load('requests.json', []);

// ── password hashing (scrypt) ──
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const h = crypto.scryptSync(pw, salt, 64).toString('hex');
  try { return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex')); }
  catch { return false; }
}

// ── sessions ──
function newSession(username) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions[token] = { username, expires: Date.now() + 30 * 24 * 3600 * 1000 };
  save('sessions.json', sessions);
  return token;
}
function userFromToken(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const sess = sessions[token];
  if (!sess) return null;
  if (sess.expires < Date.now()) { delete sessions[token]; save('sessions.json', sessions); return null; }
  return users.find(u => u.username === sess.username) || null;
}

// seed default admin on first run
if (users.length === 0) {
  users.push({ username: 'admin', pw: hashPassword('admin123'), isAdmin: true, createdAt: Date.now() });
  save('users.json', users);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 5e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
  });
}
function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function publicUser(u) {
  return { username: u.username, isAdmin: !!u.isAdmin, createdAt: u.createdAt };
}
function validateNotes(notes) {
  if (!Array.isArray(notes)) return false;
  return notes.every(n =>
    Array.isArray(n) && n.length >= 4 &&
    Number.isFinite(n[0]) && n[0] >= 0 &&
    n[1] >= 0 && n[1] <= 3 &&
    Number.isFinite(n[2]) && n[2] >= 1 &&
    (n[3] === 0 || n[3] === 1)
  );
}

// ── request router ──
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;

  try {
    if (p.startsWith('/api/')) {
      // ── AUTH ──
      if (p === '/api/register' && req.method === 'POST') {
        const b = await readBody(req);
        const username = String(b.username || '').trim();
        const password = String(b.password || '');
        if (username.length < 3 || username.length > 20) return send(res, 400, { error: '用户名需 3-20 字符' });
        if (!/^[a-zA-Z0-9_]+$/.test(username)) return send(res, 400, { error: '用户名仅限字母/数字/下划线' });
        if (password.length < 4) return send(res, 400, { error: '密码至少 4 位' });
        if (users.find(u => u.username === username)) return send(res, 409, { error: '用户名已存在' });
        users.push({ username, pw: hashPassword(password), isAdmin: false, createdAt: Date.now() });
        save('users.json', users);
        const token = newSession(username);
        return send(res, 200, { token, user: publicUser(users[users.length - 1]) });
      }
      if (p === '/api/login' && req.method === 'POST') {
        const b = await readBody(req);
        const username = String(b.username || '').trim();
        const password = String(b.password || '');
        const u = users.find(x => x.username === username);
        if (!u || !verifyPassword(password, u.pw)) return send(res, 401, { error: '用户名或密码错误' });
        const token = newSession(username);
        return send(res, 200, { token, user: publicUser(u) });
      }
      if (p === '/api/me' && req.method === 'GET') {
        const u = userFromToken(req);
        if (!u) return send(res, 401, { error: '未登录' });
        return send(res, 200, { user: publicUser(u) });
      }

      // ── ADMIN REQUEST ──
      if (p === '/api/admin-request' && req.method === 'POST') {
        const u = userFromToken(req);
        if (!u) return send(res, 401, { error: '请先登录' });
        if (u.isAdmin) return send(res, 400, { error: '你已是管理员' });
        if (requests.find(r => r.username === u.username && r.status === 'pending'))
          return send(res, 400, { error: '申请已提交，等待审核' });
        const b = await readBody(req);
        const r = { id: crypto.randomUUID(), username: u.username, message: String(b.message || '').slice(0, 200), status: 'pending', createdAt: Date.now() };
        requests.push(r);
        save('requests.json', requests);
        return send(res, 200, { ok: true, request: r });
      }
      if (p === '/api/admin-requests' && req.method === 'GET') {
        const u = userFromToken(req);
        if (!u || !u.isAdmin) return send(res, 403, { error: '无权限' });
        return send(res, 200, { requests });
      }
      const mReq = p.match(/^\/api\/admin-requests\/([\w-]+)\/(approve|reject)$/);
      if (mReq && req.method === 'POST') {
        const u = userFromToken(req);
        if (!u || !u.isAdmin) return send(res, 403, { error: '无权限' });
        const r = requests.find(x => x.id === mReq[1]);
        if (!r) return send(res, 404, { error: '申请不存在' });
        r.status = mReq[2] === 'approve' ? 'approved' : 'rejected';
        const target = users.find(x => x.username === r.username);
        if (target && mReq[2] === 'approve') target.isAdmin = true;
        save('requests.json', requests);
        save('users.json', users);
        return send(res, 200, { ok: true, request: r });
      }

      // ── CHARTS ──
      if (p === '/api/charts' && req.method === 'GET') {
        const list = charts
          .slice()
          .sort((a, b) => b.createdAt - a.createdAt)
          .map(c => ({ id: c.id, name: c.name, bpm: c.bpm, author: c.author, plays: c.plays || 0, createdAt: c.createdAt, noteCount: c.notes.length }));
        return send(res, 200, { charts: list });
      }
      if (p === '/api/charts' && req.method === 'POST') {
        const u = userFromToken(req);
        if (!u || !u.isAdmin) return send(res, 403, { error: '仅管理员可发布谱面' });
        const b = await readBody(req);
        const name = String(b.name || '').trim();
        const bpm = Number(b.bpm);
        if (!name) return send(res, 400, { error: '请填写曲名' });
        if (!Number.isFinite(bpm) || bpm < 30 || bpm > 300) return send(res, 400, { error: 'BPM 需在 30-300' });
        if (!validateNotes(b.notes)) return send(res, 400, { error: '谱面格式无效' });
        const chart = {
          id: crypto.randomUUID(), name, bpm,
          notes: b.notes, author: u.username,
          plays: 0, createdAt: Date.now()
        };
        charts.push(chart);
        save('charts.json', charts);
        return send(res, 200, { chart });
      }
      const mChart = p.match(/^\/api\/charts\/([\w-]+)$/);
      if (mChart && req.method === 'GET') {
        const c = charts.find(x => x.id === mChart[1]);
        if (!c) return send(res, 404, { error: '谱面不存在' });
        return send(res, 200, { chart: c });
      }
      if (mChart && req.method === 'POST' && p.endsWith('/play')) {
        const c = charts.find(x => x.id === mChart[1]);
        if (c) { c.plays = (c.plays || 0) + 1; save('charts.json', charts); }
        return send(res, 200, { ok: true });
      }

      return send(res, 404, { error: '接口不存在' });
    }

    // serve the SPA
    if (req.method === 'GET') {
      const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    }
    res.writeHead(404); res.end('Not found');
  } catch (e) {
    console.error(e);
    send(res, 500, { error: '服务器错误' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Musical Beats running at http://localhost:${PORT}`);
  console.log(`LAN: http://${require('os').networkInterfaces() && Object.values(require('os').networkInterfaces()).flat().find(i => i.family === 'IPv4' && !i.internal)?.address || 'localhost'}:${PORT}`);
  console.log('Default admin -> username: admin  password: admin123');
});
