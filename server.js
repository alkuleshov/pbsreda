'use strict';
/*
 * Проектное бюро «Среда» — сервер сбора документов заявки.
 * Node 20+, SQLite, файлы на диске сервера. Внешних сервисов не требует.
 *
 * Запуск:  npm install && npm start
 * Данные:  ./data/pbsreda.db, ./data/incoming, ./data/work
 */

const express = require('express');
const multer = require('multer');
const session = require('express-session');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const INCOMING = path.join(DATA, 'incoming');   // до одобрения куратором
const WORK = path.join(DATA, 'work');           // после одобрения
const PUBLIC = path.join(ROOT, 'public');       // сюда кладём html-страницы

for (const dir of [DATA, INCOMING, WORK]) fs.mkdirSync(dir, { recursive: true });

/* ---------- база ---------- */
const db = new Database(path.join(DATA, 'pbsreda.db'));
db.pragma('journal_mode = WAL');
db.exec(fs.readFileSync(path.join(ROOT, 'schema.sql'), 'utf8'));

const hash = p => crypto.scryptSync(String(p), 'pbsreda', 32).toString('hex');
const check = (p, h) => {
  const a = Buffer.from(hash(p), 'hex'), b = Buffer.from(h, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

/* первичное заполнение: 10 территорий и три кабинета, пароль 1234 */
if (!db.prepare('SELECT count(*) n FROM cities').get().n) {
  const ins = db.prepare('INSERT INTO cities (key, name, pass, active) VALUES (?, ?, ?, ?)');
  for (let i = 1; i <= 20; i++) ins.run('city' + i, 'Город ' + i, hash('1234'), i <= 4 ? 1 : 0);  // 20 адресов, открыты первые четыре
  const insRole = db.prepare('INSERT INTO roles (role, pass) VALUES (?, ?)');
  for (const r of ['crd', 'mgr', 'spec']) insRole.run(r, hash('1234'));
}

const logIt = (who, action, details = '') =>
  db.prepare('INSERT INTO log (ts, who, action, details) VALUES (?, ?, ?, ?)')
    .run(new Date().toISOString(), who, action, details);

/* ---------- приложение ---------- */
const app = express();
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(24).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 12 * 3600 * 1000 }
}));

const who = req => req.session.role === 'adm' ? 'adm:' + req.session.city : req.session.role;
const needAuth = (...roles) => (req, res, next) => {
  if (!req.session.role) return res.status(401).json({ error: 'нужен вход' });
  if (roles.length && !roles.includes(req.session.role)) return res.status(403).json({ error: 'нет доступа' });
  next();
};

/* ---------- вход ---------- */
app.get('/api/cities', (req, res) => {
  res.json(db.prepare('SELECT key, name, active FROM cities ORDER BY key').all());
});

app.post('/api/login', (req, res) => {
  const { role, city, password } = req.body || {};
  if (role === 'adm') {
    const c = db.prepare('SELECT * FROM cities WHERE key = ?').get(city);
    if (!c || !check(password, c.pass)) return res.status(401).json({ error: 'Пароль не подходит' });
    if (!c.active) return res.status(403).json({ error: 'Профайл территории ещё не открыт' });
    req.session.role = 'adm'; req.session.city = c.key;
  } else {
    const r = db.prepare('SELECT * FROM roles WHERE role = ?').get(role);
    if (!r || !check(password, r.pass)) return res.status(401).json({ error: 'Пароль не подходит' });
    req.session.role = role; req.session.city = null;
  }
  logIt(who(req), 'вход');
  res.json({ ok: true, role: req.session.role, city: req.session.city });
});

app.post('/api/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });

/* ---------- состояние ---------- */
app.get('/api/state/:city', needAuth(), (req, res) => {
  const city = req.session.role === 'adm' ? req.session.city : req.params.city;
  const c = db.prepare('SELECT key, name, budget, landing, votes, target FROM cities WHERE key = ?').get(city);
  if (!c) return res.status(404).json({ error: 'территория не найдена' });

  const reqs = db.prepare('SELECT * FROM requests WHERE city = ?').all(city);
  // администрация и куратор видят свои файлы, остальные — только одобренные
  const seeAll = req.session.role === 'adm' || req.session.role === 'crd';
  const files = db.prepare(
    'SELECT id, code, name, size, approved FROM files WHERE city = ?' + (seeAll ? '' : ' AND approved = 1')
  ).all(city);

  res.json({ role: req.session.role, city: c, requests: reqs, files, templates: db.prepare('SELECT * FROM templates').all() });
});

/* ---------- загрузка файлов ---------- */
const upload = multer({
  storage: multer.diskStorage({
    destination(req, file, cb) {
      const dir = path.join(INCOMING, req.body.city || req.session.city, req.body.code || 'разное');
      fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename(req, file, cb) {
      const orig = Buffer.from(file.originalname, 'latin1').toString('utf8');
      const stamp = new Date().toISOString().slice(0, 10);
      cb(null, stamp + '_' + orig.replace(/[/\\?%*:|"<>]/g, '-'));
    }
  }),
  limits: { fileSize: 200 * 1024 * 1024 }
});

app.post('/api/upload', needAuth('adm', 'crd'), upload.array('files', 20), (req, res) => {
  const city = req.session.role === 'adm' ? req.session.city : req.body.city;
  const code = req.body.code;
  const ins = db.prepare('INSERT INTO files (city, code, name, size, path, approved, created) VALUES (?,?,?,?,?,0,?)');
  for (const f of req.files) {
    ins.run(city, code, Buffer.from(f.originalname, 'latin1').toString('utf8'), f.size, f.path, new Date().toISOString());
  }
  db.prepare(`INSERT INTO requests (city, code, status) VALUES (?, ?, 'sent')
              ON CONFLICT(city, code) DO UPDATE SET status = 'sent', back = ''`).run(city, code);
  logIt(who(req), 'загрузка', code + ' × ' + req.files.length);
  res.json({ ok: true });
});

/* ---------- приёмка (только куратор) ---------- */
app.post('/api/approve', needAuth('crd'), (req, res) => {
  const { city, code } = req.body;
  const rows = db.prepare('SELECT * FROM files WHERE city = ? AND code = ? AND approved = 0').all(city, code);
  const upd = db.prepare('UPDATE files SET approved = 1, path = ? WHERE id = ?');
  for (const f of rows) {
    const dir = path.join(WORK, city, code);
    fs.mkdirSync(dir, { recursive: true });
    const dest = path.join(dir, path.basename(f.path));
    fs.renameSync(f.path, dest);
    upd.run(dest, f.id);
  }
  db.prepare("UPDATE requests SET status = 'ok', back = '' WHERE city = ? AND code = ?").run(city, code);
  logIt(who(req), 'одобрено', city + ' / ' + code);
  res.json({ ok: true });
});

app.post('/api/return', needAuth('crd'), (req, res) => {
  const { city, code, text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'нужен текст замечания' });
  for (const f of db.prepare('SELECT * FROM files WHERE city = ? AND code = ?').all(city, code)) {
    try { fs.unlinkSync(f.path); } catch (e) {}
  }
  db.prepare('DELETE FROM files WHERE city = ? AND code = ?').run(city, code);
  db.prepare("UPDATE requests SET status = 'none', back = ? WHERE city = ? AND code = ?").run(text, city, code);
  logIt(who(req), 'возврат', city + ' / ' + code);
  res.json({ ok: true });
});

app.post('/api/file/delete', needAuth('crd'), (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id = ?').get(req.body.id);
  if (!f) return res.status(404).json({ error: 'файл не найден' });
  try { fs.unlinkSync(f.path); } catch (e) {}
  db.prepare('DELETE FROM files WHERE id = ?').run(f.id);
  if (!db.prepare('SELECT count(*) n FROM files WHERE city = ? AND code = ?').get(f.city, f.code).n)
    db.prepare("UPDATE requests SET status = 'none' WHERE city = ? AND code = ?").run(f.city, f.code);
  logIt(who(req), 'удаление файла', f.city + ' / ' + f.code + ' / ' + f.name);
  res.json({ ok: true });
});

app.get('/api/file/:id', needAuth(), (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!f) return res.sendStatus(404);
  if (req.session.role === 'adm' && f.city !== req.session.city) return res.sendStatus(403);
  if (!f.approved && !['adm', 'crd'].includes(req.session.role)) return res.sendStatus(403);
  res.download(f.path, f.name);
});

/* ---------- поля запроса ---------- */
app.post('/api/request', needAuth('adm', 'crd', 'spec'), (req, res) => {
  const { city, code, field, value } = req.body;
  const allowed = { adm: ['fio', 'contact', 'note'], crd: ['deadline'], spec: ['done'] };
  if (!allowed[req.session.role].includes(field)) return res.status(403).json({ error: 'поле недоступно' });
  const target = req.session.role === 'adm' ? req.session.city : city;
  db.prepare('INSERT INTO requests (city, code) VALUES (?, ?) ON CONFLICT DO NOTHING').run(target, code);
  db.prepare('UPDATE requests SET ' + field + ' = ? WHERE city = ? AND code = ?').run(value, target, code);
  res.json({ ok: true });
});

/* ---------- настройки территорий (куратор) ---------- */
app.post('/api/city', needAuth('crd'), (req, res) => {
  const { key, name, pass, budget, landing, votes, target, active } = req.body;
  const c = db.prepare('SELECT * FROM cities WHERE key = ?').get(key);
  if (!c) return res.status(404).json({ error: 'территория не найдена' });
  db.prepare(`UPDATE cities SET name = ?, budget = ?, landing = ?, votes = ?, target = ?, active = ?
              ${pass ? ', pass = ?' : ''} WHERE key = ?`)
    .run(...[name, budget || '', landing || '', +votes || 0, +target || 0, active ? 1 : 0]
      .concat(pass ? [hash(pass)] : []).concat([key]));
  logIt(who(req), 'настройки территории', key);
  res.json({ ok: true });
});

/* закрытие территории: доступ отключается, файлы живут ещё 30 дней */
app.post('/api/city/close', needAuth('crd'), (req, res) => {
  db.prepare("UPDATE cities SET active = 0, closed_at = ? WHERE key = ?")
    .run(new Date().toISOString(), req.body.key);
  logIt(who(req), 'территория закрыта', req.body.key);
  res.json({ ok: true });
});

app.post('/api/city/reopen', needAuth('crd'), (req, res) => {
  db.prepare("UPDATE cities SET active = 1, closed_at = '' WHERE key = ?").run(req.body.key);
  logIt(who(req), 'территория открыта снова', req.body.key);
  res.json({ ok: true });
});

/* окончательное удаление — только вручную и только для закрытой территории */
app.post('/api/city/purge', needAuth('crd'), (req, res) => {
  const { key, confirmName } = req.body;
  const c = db.prepare('SELECT * FROM cities WHERE key = ?').get(key);
  if (!c) return res.status(404).json({ error: 'территория не найдена' });
  if (!c.closed_at) return res.status(400).json({ error: 'сначала закройте территорию' });
  if (confirmName !== c.name) return res.status(400).json({ error: 'название не совпадает' });
  purge(key);
  logIt(who(req), 'территория удалена навсегда', key);
  res.json({ ok: true });
});

function purge(key){
  for (const f of db.prepare('SELECT * FROM files WHERE city = ?').all(key)) {
    try { fs.unlinkSync(f.path); } catch (e) {}
  }
  db.prepare('DELETE FROM files WHERE city = ?').run(key);
  db.prepare('DELETE FROM requests WHERE city = ?').run(key);
  const i = key.replace('city', '');
  db.prepare("UPDATE cities SET name = ?, pass = ?, budget = '', landing = '', votes = 0, target = 0, active = 0, closed_at = '' WHERE key = ?")
    .run('Город ' + i, hash('1234'), key);
  for (const dir of [path.join(INCOMING, key), path.join(WORK, key)]) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
  }
}

/* ежедневная уборка: territории, закрытые больше 30 дней назад */
function autoPurge(){
  const edge = Date.now() - 30 * 24 * 3600 * 1000;
  for (const c of db.prepare("SELECT * FROM cities WHERE closed_at <> ''").all()) {
    if (new Date(c.closed_at).getTime() < edge) { purge(c.key); logIt('система', 'автоудаление через 30 дней', c.key); }
  }
}
setInterval(autoPurge, 6 * 3600 * 1000);
autoPurge();

app.post('/api/role-pass', needAuth('crd'), (req, res) => {
  const { role, pass } = req.body;
  if (!['crd', 'mgr', 'spec'].includes(role) || !pass) return res.status(400).json({ error: 'проверьте данные' });
  db.prepare('UPDATE roles SET pass = ? WHERE role = ?').run(hash(pass), role);
  logIt(who(req), 'смена пароля кабинета', role);
  res.json({ ok: true });
});

/* ---------- страницы ---------- */
app.use(express.static(PUBLIC, { extensions: ['html'] }));   // /city1 отдаёт city1.html
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC, 'index.html')));

app.listen(PORT, () => console.log('pbsreda: http://127.0.0.1:' + PORT));
