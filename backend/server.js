const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

// Ensure data directory exists
const dataDir = '/app/data';
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Database setup
const db = new Database(path.join(dataDir, 'geogame.db'));
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
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
`);

// Migrate: add is_admin column if it doesn't exist yet (for existing databases)
try { db.exec(`ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0`); } catch {}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Admin middleware
function adminOnly(req, res, next) {
  const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.user.id);
  if (!user?.is_admin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

// Register
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 2 || username.length > 20) return res.status(400).json({ error: 'Username must be 2-20 characters' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });

  const hash = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
    const result = stmt.run(username.trim(), hash);
    const token = jwt.sign({ id: result.lastInsertRowid, username: username.trim() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username: username.trim(), is_admin: 0 });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Username already taken' });
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username?.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username, is_admin: user.is_admin });
});

const VALID_DIFFICULTIES = ['easy', 'medium', 'jeroen'];

// Submit score
app.post('/api/scores', auth, (req, res) => {
  const { streak, difficulty } = req.body;
  if (typeof streak !== 'number' || streak < 0) return res.status(400).json({ error: 'Invalid streak' });
  if (!VALID_DIFFICULTIES.includes(difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  db.prepare('INSERT INTO scores (user_id, streak, difficulty) VALUES (?, ?, ?)').run(req.user.id, streak, difficulty);
  res.json({ ok: true });
});

// Leaderboard
app.get('/api/leaderboard', (req, res) => {
  const difficulty = req.query.difficulty || 'medium';
  if (!VALID_DIFFICULTIES.includes(difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  const rows = db.prepare(`
    SELECT u.username, MAX(s.streak) as best_streak, COUNT(s.id) as games_played
    FROM users u
    JOIN scores s ON s.user_id = u.id
    WHERE s.difficulty = ?
    GROUP BY u.id
    ORDER BY best_streak DESC
    LIMIT 20
  `).all(difficulty);
  res.json(rows);
});

// My stats per difficulty
app.get('/api/me/stats', auth, (req, res) => {
  const stats = {};
  for (const diff of VALID_DIFFICULTIES) {
    const best = db.prepare('SELECT MAX(streak) as best FROM scores WHERE user_id = ? AND difficulty = ?').get(req.user.id, diff);
    const count = db.prepare('SELECT COUNT(*) as total FROM scores WHERE user_id = ? AND difficulty = ?').get(req.user.id, diff);
    stats[diff] = { best_streak: best?.best || 0, games_played: count?.total || 0 };
  }
  res.json(stats);
});

// ── ADMIN ROUTES ──

// List all users
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.is_admin, u.created_at,
      COUNT(s.id) as games_played
    FROM users u
    LEFT JOIN scores s ON s.user_id = u.id
    GROUP BY u.id
    ORDER BY u.created_at ASC
  `).all();
  res.json(users);
});

// Promote/demote admin
app.post('/api/admin/users/:id/set-admin', auth, adminOnly, (req, res) => {
  const { is_admin } = req.body;
  if (typeof is_admin !== 'number') return res.status(400).json({ error: 'Invalid value' });
  if (parseInt(req.params.id) === req.user.id && !is_admin) {
    return res.status(400).json({ error: 'Cannot remove your own admin status' });
  }
  db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(is_admin, req.params.id);
  res.json({ ok: true });
});

// Delete user
app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  if (parseInt(req.params.id) === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete yourself' });
  }
  db.prepare('DELETE FROM scores WHERE user_id = ?').run(req.params.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Clear all scores for a difficulty
app.delete('/api/admin/scores', auth, adminOnly, (req, res) => {
  const { difficulty } = req.query;
  if (!VALID_DIFFICULTIES.includes(difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  db.prepare('DELETE FROM scores WHERE difficulty = ?').run(difficulty);
  res.json({ ok: true });
});

// Clear scores for a specific user on a specific difficulty
app.delete('/api/admin/scores/user/:id', auth, adminOnly, (req, res) => {
  const { difficulty } = req.query;
  if (difficulty && !VALID_DIFFICULTIES.includes(difficulty)) return res.status(400).json({ error: 'Invalid difficulty' });
  if (difficulty) {
    db.prepare('DELETE FROM scores WHERE user_id = ? AND difficulty = ?').run(req.params.id, difficulty);
  } else {
    db.prepare('DELETE FROM scores WHERE user_id = ?').run(req.params.id);
  }
  res.json({ ok: true });
});

// Catch-all: serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`GeoGame running on port ${PORT}`));
