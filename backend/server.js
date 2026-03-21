const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many attempts' }, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60*1000, max: 120, message: { error: 'Too many requests' }, standardHeaders: true, legacyHeaders: false });

const dataDir = '/app/data';
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'geogame.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    temp_password TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    streak INTEGER NOT NULL,
    difficulty TEXT NOT NULL DEFAULT 'medium',
    played_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

// Migrations
try { db.exec(`ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN temp_password TEXT`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'en'`); } catch {}

const DEFAULT_SETTINGS = {
  easy_timer_simple: '5', easy_timer_match: '30', easy_timer_map: '0',
  medium_timer_simple: '0', medium_timer_match: '0', medium_timer_map: '0',
  jeroen_timer_simple: '12', jeroen_timer_match: '60', jeroen_timer_map: '30',
  jeroen_timer_typed: '15', jeroen_timer_capitalmap: '30',
  jeroen_map_threshold: '400',
  jeroen_show_historical_label: '1', jeroen_historical_flags: '1', jeroen_historical_capitals: '0',
  medium_pop_margin: '20',
  jeroen_pop_margin: '10',
  medium_second_city: '1',
};
for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
  try { db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run(key, value); } catch {}
}

function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : DEFAULT_SETTINGS[key];
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/', apiLimiter);

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminOnly(req, res, next) {
  const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.user.id);
  if (!user?.is_admin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 2 || username.length > 20) return res.status(400).json({ error: 'Username must be 2-20 characters' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username.trim(), hash);
    const token = jwt.sign({ id: result.lastInsertRowid, username: username.trim() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: username.trim(), is_admin: 0, language: 'en' });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username already taken' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username?.trim());
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });
  const pwMatch = bcrypt.compareSync(password, user.password_hash);
  const tmpMatch = user.temp_password && user.temp_password === password;
  if (!pwMatch && !tmpMatch) return res.status(401).json({ error: 'Invalid username or password' });
  if (tmpMatch) db.prepare('UPDATE users SET temp_password = NULL WHERE id = ?').run(user.id);
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username, is_admin: user.is_admin, must_change_password: tmpMatch ? 1 : 0, language: user.language || 'en' });
});

const VALID_DIFFICULTIES = ['easy', 'medium', 'jeroen'];

app.get('/api/settings', (req, res) => {
  res.json({
    easy_timer_simple: parseInt(getSetting('easy_timer_simple')),
    easy_timer_match: parseInt(getSetting('easy_timer_match')),
    easy_timer_map: parseInt(getSetting('easy_timer_map')),
    medium_timer_simple: parseInt(getSetting('medium_timer_simple')),
    medium_timer_match: parseInt(getSetting('medium_timer_match')),
    medium_timer_map: parseInt(getSetting('medium_timer_map')),
    jeroen_timer_simple: parseInt(getSetting('jeroen_timer_simple')),
    jeroen_timer_match: parseInt(getSetting('jeroen_timer_match')),
    jeroen_timer_map: parseInt(getSetting('jeroen_timer_map')),
    jeroen_timer_typed: parseInt(getSetting('jeroen_timer_typed')),
    jeroen_timer_capitalmap: parseInt(getSetting('jeroen_timer_capitalmap')),
    jeroen_map_threshold: parseInt(getSetting('jeroen_map_threshold')),
    jeroen_show_historical_label: getSetting('jeroen_show_historical_label') === '1',
    jeroen_historical_flags: getSetting('jeroen_historical_flags') === '1',
    jeroen_historical_capitals: getSetting('jeroen_historical_capitals') === '1',
    medium_pop_margin: parseInt(getSetting('medium_pop_margin')),
    jeroen_pop_margin: parseInt(getSetting('jeroen_pop_margin')),
    medium_second_city: getSetting('medium_second_city') !== '0',
  });
});

app.post('/api/scores', auth, (req, res) => {
  const { streak, difficulty } = req.body;
  if (typeof streak !== 'number' || streak < 0) return res.status(400).json({ error: 'Invalid streak' });
  if (!VALID_DIFFICULTIES.includes(difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  db.prepare('INSERT INTO scores (user_id, streak, difficulty) VALUES (?, ?, ?)').run(req.user.id, streak, difficulty);
  res.json({ ok: true });
});

app.get('/api/leaderboard', (req, res) => {
  const difficulty = req.query.difficulty || 'medium';
  if (!VALID_DIFFICULTIES.includes(difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  const rows = db.prepare(`
    SELECT u.username, MAX(s.streak) as best_streak, COUNT(s.id) as games_played
    FROM users u JOIN scores s ON s.user_id = u.id
    WHERE s.difficulty = ?
    GROUP BY u.id ORDER BY best_streak DESC LIMIT 20
  `).all(difficulty);
  res.json(rows);
});

app.get('/api/me/stats', auth, (req, res) => {
  const stats = {};
  for (const diff of VALID_DIFFICULTIES) {
    const best = db.prepare('SELECT MAX(streak) as best FROM scores WHERE user_id = ? AND difficulty = ?').get(req.user.id, diff);
    const count = db.prepare('SELECT COUNT(*) as total FROM scores WHERE user_id = ? AND difficulty = ?').get(req.user.id, diff);
    stats[diff] = { best_streak: best?.best || 0, games_played: count?.total || 0 };
  }
  res.json(stats);
});

app.post('/api/me/change-password', auth, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET password_hash = ?, temp_password = NULL WHERE id = ?').run(hash, req.user.id);
  res.json({ ok: true });
});

app.post('/api/me/language', auth, (req, res) => {
  const { language } = req.body;
  if (!['en', 'nl'].includes(language)) return res.status(400).json({ error: 'Invalid language' });
  db.prepare('UPDATE users SET language = ? WHERE id = ?').run(language, req.user.id);
  res.json({ ok: true });
});

app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.is_admin, u.created_at, u.temp_password,
      COUNT(s.id) as games_played
    FROM users u LEFT JOIN scores s ON s.user_id = u.id
    GROUP BY u.id ORDER BY u.created_at ASC
  `).all();
  res.json(users);
});

app.post('/api/admin/users/:id/set-admin', auth, adminOnly, (req, res) => {
  const { is_admin } = req.body;
  if (typeof is_admin !== 'number') return res.status(400).json({ error: 'Invalid value' });
  if (parseInt(req.params.id) === req.user.id && !is_admin)
    return res.status(400).json({ error: 'Cannot remove your own admin status' });
  db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(is_admin, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  if (parseInt(req.params.id) === req.user.id)
    return res.status(400).json({ error: 'Cannot delete yourself' });
  db.prepare('DELETE FROM scores WHERE user_id = ?').run(req.params.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/reset-password', auth, adminOnly, (req, res) => {
  const temp = crypto.randomBytes(3).toString('hex').toUpperCase();
  db.prepare('UPDATE users SET temp_password = ? WHERE id = ?').run(temp, req.params.id);
  res.json({ temp_password: temp });
});

app.delete('/api/admin/scores', auth, adminOnly, (req, res) => {
  const { difficulty } = req.query;
  if (!VALID_DIFFICULTIES.includes(difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  db.prepare('DELETE FROM scores WHERE difficulty = ?').run(difficulty);
  res.json({ ok: true });
});

app.delete('/api/admin/scores/user/:id', auth, adminOnly, (req, res) => {
  const { difficulty } = req.query;
  if (difficulty && !VALID_DIFFICULTIES.includes(difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  if (difficulty) db.prepare('DELETE FROM scores WHERE user_id = ? AND difficulty = ?').run(req.params.id, difficulty);
  else db.prepare('DELETE FROM scores WHERE user_id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/settings', auth, adminOnly, (req, res) => {
  const allowed = [
    'easy_timer_simple','easy_timer_match','easy_timer_map',
    'medium_timer_simple','medium_timer_match','medium_timer_map',
    'jeroen_timer_simple','jeroen_timer_match','jeroen_timer_map','jeroen_timer_typed','jeroen_timer_capitalmap',
    'jeroen_map_threshold','jeroen_show_historical_label','jeroen_historical_flags','jeroen_historical_capitals',
    'medium_pop_margin','jeroen_pop_margin','medium_second_city',
  ];
  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, String(req.body[key]));
    }
  }
  res.json({ ok: true });
});

app.get('*', (req, res) => {
  const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
  const token = process.env.MAPBOX_TOKEN || '';
  res.send(html.replace('__MAPBOX_TOKEN__', token));
});

app.listen(PORT, () => console.log(`GeoGame running on port ${PORT}`));
