// Racha SG — dividir despesas a dois (sem dependências externas)
// Uso: RACHA_PIN=1234 PORT=3099 RACHA_DATA=~/racha-data node server.js
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3099);
const PIN = String(process.env.RACHA_PIN || '');
const DATA_DIR = process.env.RACHA_DATA || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'racha.json');
const PUBLIC = path.join(__dirname, 'public');

if (!PIN) { console.error('Defina RACHA_PIN (ex.: RACHA_PIN=123456 node server.js)'); process.exit(1); }
fs.mkdirSync(DATA_DIR, { recursive: true });

const SECRET_FILE = path.join(DATA_DIR, '.secret');
if (!fs.existsSync(SECRET_FILE)) fs.writeFileSync(SECRET_FILE, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
const SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();

const EMPTY = { pessoas: ['Sophia', 'Namorada'], grupos: [], despesas: [] };
function load() {
  try { return Object.assign(structuredClone(EMPTY), JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'))); }
  catch { return structuredClone(EMPTY); }
}
function save(db) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DATA_FILE);
  const bk = path.join(DATA_DIR, 'backup-' + new Date().toISOString().slice(0, 10) + '.json');
  if (!fs.existsSync(bk)) fs.copyFileSync(DATA_FILE, bk);
}

// ---- sessão ----
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const makeToken = () => { const exp = String(Date.now() + 1000 * 60 * 60 * 24 * 90); return exp + '.' + sign(exp); };
function validToken(t) {
  if (!t) return false;
  const [exp, sig] = t.split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const good = sign(exp);
  return sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
}
function cookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
const fails = new Map();
const blocked = ip => { const f = fails.get(ip); return f && f.n >= 5 && Date.now() - f.t < 15 * 60 * 1000; };
const fail = ip => { const f = fails.get(ip) || { n: 0, t: 0 }; f.n++; f.t = Date.now(); fails.set(ip, f); };

// ---- utilidades ----
const id = () => crypto.randomUUID().slice(0, 12);
const num = v => Math.round((Number(String(v ?? '').replace(',', '.')) || 0) * 100) / 100;
const txt = (v, n = 80) => String(v ?? '').trim().slice(0, n);
function send(res, code, obj, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
}
function body(req) {
  return new Promise((ok, ko) => {
    let s = ''; req.on('data', c => { s += c; if (s.length > 1e6) req.destroy(); });
    req.on('end', () => { try { ok(s ? JSON.parse(s) : {}); } catch { ko(new Error('json')); } });
  });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };

function limparDespesa(b, db) {
  const pessoas = db.pessoas;
  const d = {
    grupo: txt(b.grupo, 20), desc: txt(b.desc), valor: num(b.valor),
    pagou: pessoas.includes(b.pagou) ? b.pagou : pessoas[0],
    data: /^\d{4}-\d{2}-\d{2}$/.test(b.data) ? b.data : new Date().toISOString().slice(0, 10),
    tipo: ['igual', 'valores', 'reembolso'].includes(b.tipo) ? b.tipo : 'igual',
    partes: {}
  };
  // partes: quanto cada pessoa "consumiu" da despesa
  if (d.tipo === 'igual') {
    const quem = (Array.isArray(b.entre) ? b.entre : pessoas).filter(p => pessoas.includes(p));
    const lista = quem.length ? quem : pessoas;
    let resto = Math.round(d.valor * 100);
    lista.forEach((p, i) => { const c = i === lista.length - 1 ? resto : Math.round(d.valor * 100 / lista.length); d.partes[p] = c / 100; resto -= c; });
  } else {
    pessoas.forEach(p => { const v = num(b.partes?.[p]); if (v) d.partes[p] = v; });
    if (d.tipo === 'valores') d.valor = num(Object.values(d.partes).reduce((s, v) => s + v, 0));
  }
  return d;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;

    if (p === '/api/login' && req.method === 'POST') {
      if (blocked(ip)) return send(res, 429, { erro: 'Muitas tentativas. Espere 15 minutos.' });
      const b = await body(req);
      if (String(b.pin || '') !== PIN) { fail(ip); return send(res, 401, { erro: 'PIN incorreto' }); }
      fails.delete(ip);
      return send(res, 200, { ok: true }, { 'Set-Cookie': `racha=${makeToken()}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 90}` });
    }
    if (p === '/api/logout') return send(res, 200, { ok: true }, { 'Set-Cookie': 'racha=; Path=/; Max-Age=0' });

    if (p.startsWith('/api/')) {
      if (!validToken(cookie(req, 'racha'))) return send(res, 401, { erro: 'login' });
      const db = load();
      const [, coll, rid] = p.split('/').filter(Boolean);
      const ok = () => { save(db); send(res, 200, db); };

      if (coll === 'state' && req.method === 'GET') return send(res, 200, db);

      if (coll === 'pessoas' && req.method === 'PUT') {
        const b = await body(req);
        const novos = [txt(b.a, 30), txt(b.b, 30)];
        if (!novos[0] || !novos[1] || novos[0] === novos[1]) return send(res, 400, { erro: 'Nomes inválidos' });
        const troca = n => { const i = db.pessoas.indexOf(n); return i >= 0 ? novos[i] : n; };
        db.despesas.forEach(d => { d.pagou = troca(d.pagou); const np = {}; for (const [k, v] of Object.entries(d.partes)) np[troca(k)] = v; d.partes = np; });
        db.pessoas = novos; return ok();
      }

      if (coll === 'grupos') {
        if (req.method === 'POST') { const b = await body(req); const nome = txt(b.nome, 40); if (!nome) return send(res, 400, { erro: 'Nome' }); db.grupos.push({ id: id(), nome, criado: Date.now() }); return ok(); }
        const g = db.grupos.find(x => x.id === rid); if (!g) return send(res, 404, { erro: 'Grupo não encontrado' });
        if (req.method === 'PUT') { const b = await body(req); g.nome = txt(b.nome, 40) || g.nome; if ('arquivado' in b) g.arquivado = !!b.arquivado; return ok(); }
        if (req.method === 'DELETE') { db.grupos = db.grupos.filter(x => x.id !== rid); db.despesas = db.despesas.filter(d => d.grupo !== rid); return ok(); }
      }

      if (coll === 'despesas') {
        if (req.method === 'POST' && rid === 'excluir') { // exclusão em lote
          const b = await body(req); const ids = new Set(Array.isArray(b.ids) ? b.ids : []);
          db.despesas = db.despesas.filter(d => !ids.has(d.id)); return ok();
        }
        if (req.method === 'POST') { const b = await body(req); const d = limparDespesa(b, db); if (!d.desc || !d.valor) return send(res, 400, { erro: 'Preencha descrição e valor' }); db.despesas.push({ id: id(), ...d, criado: Date.now() }); return ok(); }
        const i = db.despesas.findIndex(x => x.id === rid); if (i < 0) return send(res, 404, { erro: 'Despesa não encontrada' });
        if (req.method === 'PUT') { const b = await body(req); const d = limparDespesa({ grupo: db.despesas[i].grupo, ...b }, db); db.despesas[i] = { ...db.despesas[i], ...d }; return ok(); }
        if (req.method === 'DELETE') { db.despesas.splice(i, 1); return ok(); }
      }
      return send(res, 404, { erro: 'não encontrado' });
    }

    // ---- arquivos ----
    let f = path.normalize(path.join(PUBLIC, p === '/' ? 'index.html' : p));
    if (!f.startsWith(PUBLIC) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) f = path.join(PUBLIC, 'index.html');
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': f.endsWith('.html') ? 'no-cache' : 'max-age=86400' });
    fs.createReadStream(f).pipe(res);
  } catch (e) { console.error(e); send(res, 500, { erro: 'Erro no servidor' }); }
});
server.listen(PORT, () => console.log(`Racha SG rodando na porta ${PORT}`));
