const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const production = process.env.NODE_ENV === 'production';
if (production && !process.env.SESSION_SECRET) throw new Error('SESSION_SECRET is required in production.');

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'roomsync.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS profiles (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 display_name TEXT NOT NULL,
 age INTEGER NOT NULL CHECK(age >= 18),
 gender TEXT NOT NULL CHECK(gender IN ('woman','man')),
 city TEXT NOT NULL,
 area TEXT NOT NULL DEFAULT '',
 budget INTEGER NOT NULL,
 sleep TEXT NOT NULL CHECK(sleep IN ('early','flex','late')),
 tidy INTEGER NOT NULL DEFAULT 1,
 smoking_ok INTEGER NOT NULL DEFAULT 0,
 guests_ok INTEGER NOT NULL DEFAULT 1,
 pets_ok INTEGER NOT NULL DEFAULT 0,
 about TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 reporter_id INTEGER NOT NULL REFERENCES users(id),
 reported_user_id INTEGER NOT NULL REFERENCES users(id),
 reason TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(reporter_id, reported_user_id)
);`);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
 name: 'roomsync.sid',
 secret: process.env.SESSION_SECRET || 'local-development-secret-change-me',
 resave: false,
 saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: 'lax', secure: production, maxAge: 8 * 60 * 60 * 1000 }
}));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });
app.use('/api/register', authLimiter);
app.use('/api/login', authLimiter);
app.use(express.static(path.join(__dirname, 'public')));

const profileQuery = db.prepare(`SELECT user_id AS id, display_name AS displayName, age, gender, city, area,
 budget, sleep, tidy, smoking_ok AS smokingOk, guests_ok AS guestsOk, pets_ok AS petsOk, about
 FROM profiles WHERE user_id = ?`);
const clean = (v, max = 80) => typeof v === 'string' ? v.trim().slice(0, max) : '';
const asBool = v => v === true || v === 'true' || v === 1;
const requireAuth = (req, res, next) => req.session.userId ? next() : res.status(401).json({ error: 'Please log in first.' });
function parseProfile(body) {
 const age = Number(body.age), budget = Number(body.budget), gender = body.gender, sleep = body.sleep;
 if (!Number.isInteger(age) || age < 18 || age > 100) throw new Error('RoomSync is for adults aged 18 and over.');
 if (!['woman', 'man'].includes(gender)) throw new Error('Choose woman or man.');
 if (!Number.isInteger(budget) || budget < 1000 || budget > 1000000) throw new Error('Enter a valid monthly budget.');
 if (!['early', 'flex', 'late'].includes(sleep)) throw new Error('Choose a valid sleep schedule.');
 const displayName = clean(body.displayName, 40), city = clean(body.city, 60);
 if (displayName.length < 2 || city.length < 2) throw new Error('Enter a display name and city.');
 return { displayName, age, gender, city, area: clean(body.area, 60), budget, sleep,
  tidy: asBool(body.tidy) ? 1 : 0, smokingOk: asBool(body.smokingOk) ? 1 : 0,
  guestsOk: asBool(body.guestsOk) ? 1 : 0, petsOk: asBool(body.petsOk) ? 1 : 0, about: clean(body.about, 300) };
}

app.post('/api/register', async (req, res) => {
 try {
  const email = clean(req.body.email, 254).toLowerCase(), password = req.body.password;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (typeof password !== 'string' || password.length < 10 || password.length > 200) return res.status(400).json({ error: 'Password must be at least 10 characters.' });
  const hash = await bcrypt.hash(password, 12);
  const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, hash);
  req.session.userId = Number(result.lastInsertRowid);
  res.status(201).json({ message: 'Account created.', user: { id: req.session.userId, email } });
 } catch (err) {
  if (String(err.code) === 'SQLITE_CONSTRAINT_UNIQUE') return res.status(409).json({ error: 'That email is already registered.' });
  console.error(err); res.status(500).json({ error: 'Could not create account.' });
 }
});
app.post('/api/login', async (req, res) => {
 const email = clean(req.body.email, 254).toLowerCase(), password = req.body.password;
 const user = db.prepare('SELECT id,email,password_hash FROM users WHERE email=?').get(email);
 if (!user || typeof password !== 'string' || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
 req.session.regenerate(err => {
  if (err) return res.status(500).json({ error: 'Could not start session.' });
  req.session.userId = user.id; res.json({ message: 'Logged in.', user: { id: user.id, email: user.email } });
 });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => { res.clearCookie('roomsync.sid'); res.json({ message: 'Logged out.' }); }));
app.get('/api/me', requireAuth, (req, res) => {
 const user = db.prepare('SELECT id,email FROM users WHERE id=?').get(req.session.userId);
 res.json({ user, profile: profileQuery.get(req.session.userId) || null });
});
app.put('/api/profile', requireAuth, (req, res) => {
 try {
  const p = parseProfile(req.body);
  db.prepare(`INSERT INTO profiles (user_id,display_name,age,gender,city,area,budget,sleep,tidy,smoking_ok,guests_ok,pets_ok,about)
   VALUES (@userId,@displayName,@age,@gender,@city,@area,@budget,@sleep,@tidy,@smokingOk,@guestsOk,@petsOk,@about)
   ON CONFLICT(user_id) DO UPDATE SET display_name=excluded.display_name,age=excluded.age,gender=excluded.gender,
   city=excluded.city,area=excluded.area,budget=excluded.budget,sleep=excluded.sleep,tidy=excluded.tidy,
   smoking_ok=excluded.smoking_ok,guests_ok=excluded.guests_ok,pets_ok=excluded.pets_ok,about=excluded.about,updated_at=CURRENT_TIMESTAMP`)
   .run({ userId: req.session.userId, ...p });
  res.json({ message: 'Profile saved.', profile: profileQuery.get(req.session.userId) });
 } catch (err) { res.status(400).json({ error: err.message || 'Invalid profile.' }); }
});
function compatibility(a,b) {
 let score = 25 * Math.max(0, 1 - Math.abs(a.budget-b.budget)/25000);
 score += 15 * (a.area && b.area.toLowerCase() === a.area.toLowerCase() ? 1 : .5);
 score += 15 * (a.sleep === b.sleep ? 1 : (a.sleep === 'flex' || b.sleep === 'flex' ? .65 : 0));
 for (const k of ['tidy','smokingOk','guestsOk','petsOk']) score += 11.25 * (a[k] === b[k] ? 1 : 0);
 return Math.round(score);
}
app.get('/api/matches', requireAuth, (req,res) => {
 const me = profileQuery.get(req.session.userId);
 if (!me) return res.status(400).json({ error: 'Complete your profile first.' });
 // Gender equality is enforced by this server-side SQL filter, not trusted to the browser.
 const rows = db.prepare(`SELECT user_id AS id,display_name AS displayName,age,gender,city,area,budget,sleep,
 tidy,smoking_ok AS smokingOk,guests_ok AS guestsOk,pets_ok AS petsOk,about FROM profiles
 WHERE user_id != ? AND gender = ? AND lower(city)=lower(?)
 AND user_id NOT IN (SELECT reported_user_id FROM reports WHERE reporter_id=?)
 AND user_id NOT IN (SELECT reporter_id FROM reports WHERE reported_user_id=?)`)
 .all(req.session.userId, me.gender, me.city, req.session.userId, req.session.userId);
 res.json({ matches: rows.map(p => ({ ...p, score: compatibility(me,p) })).sort((a,b) => b.score-a.score) });
});
app.post('/api/report/:userId', requireAuth, (req,res) => {
 const id = Number(req.params.userId), reason = clean(req.body.reason,300);
 if (!Number.isInteger(id) || id === req.session.userId || !reason) return res.status(400).json({ error: 'Provide a valid user and reason.' });
 if (!db.prepare('SELECT user_id FROM profiles WHERE user_id=?').get(id)) return res.status(404).json({ error: 'Profile not found.' });
 try { db.prepare('INSERT INTO reports (reporter_id,reported_user_id,reason) VALUES (?,?,?)').run(req.session.userId,id,reason); res.json({ message: 'Report submitted.' }); }
 catch { res.status(409).json({ error: 'You have already reported this profile.' }); }
});
app.get('/api/health', (_req,res) => res.json({ status: 'ok' }));
app.get('*', (_req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT, () => console.log(`RoomSync running at http://localhost:${PORT}`));
