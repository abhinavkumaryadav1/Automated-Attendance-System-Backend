const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;
const TOKEN_INTERVAL_MS = 10_000; // 10 seconds
const isProd = process.env.NODE_ENV === 'production';
const DEPLOY_VERSION = 'cors-v3-2026-09-25';

const defaultOrigins = [
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:4173',
  'http://127.0.0.1:4173',
  'https://automated-attendance-system-frontend-ezi95kkxk.vercel.app',
  'https://automated-attendance-system-fronten-two.vercel.app',
];

const allowedOrigins = [
  ...defaultOrigins,
  ...(process.env.FRONTEND_URL || '')
    .split(',')
    .map((s) => s.trim().replace(/\/$/, ''))
    .filter(Boolean),
].filter((v, i, arr) => arr.indexOf(v) === i);

function isAllowedOrigin(origin) {
  if (!origin) return true;
  const clean = origin.replace(/\/$/, '');
  if (allowedOrigins.includes(clean)) return true;
  try {
    const url = new URL(clean);
    if (url.protocol === 'https:' && url.hostname.endsWith('.vercel.app')) {
      return true;
    }
  } catch {
    /* ignore */
  }
  return false;
}

const users = [
  { id: 't1', username: 'teacher', name: 'Alex Morgan', role: 'teacher', password: 'teacher123' },
  { id: 's1', username: 'student1', name: 'Jordan Lee', role: 'student', password: 'student123' },
  { id: 's2', username: 'student2', name: 'Sam Rivera', role: 'student', password: 'student123' },
  { id: 's3', username: 'student3', name: 'Casey Kim', role: 'student', password: 'student123' },
];

users.forEach((u) => {
  u.passwordHash = bcrypt.hashSync(u.password, 8);
  delete u.password;
});

/** @type {Map<string, object>} */
const attendanceSessions = new Map();

app.set('trust proxy', 1);

// Explicit CORS + preflight (must be first). Do not rely on cors package alone.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  return next();
});

app.use(express.json());
app.use(cookieParser());

const cookieOptions = {
  maxAge: 8 * 60 * 60 * 1000,
  httpOnly: true,
  secure: isProd,
  sameSite: isProd ? 'none' : 'lax',
};

app.use(
  session({
    name: 'pulsemark.sid',
    secret: process.env.SESSION_SECRET || 'qr-attendance-dev-secret-change-in-prod',
    resave: false,
    saveUninitialized: false,
    cookie: cookieOptions,
  })
);

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }
  req.user = { id: user.id, username: user.username, name: user.name, role: user.role };
  next();
}

function requireTeacher(req, res, next) {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: 'Teachers only' });
  }
  next();
}

function publicUser(user) {
  return { id: user.id, username: user.username, name: user.name, role: user.role };
}

function rotateToken(sess) {
  sess.previousToken = sess.currentToken;
  sess.currentToken = crypto.randomBytes(16).toString('hex');
  sess.tokenIssuedAt = Date.now();
  sess.tokenVersion += 1;
}

function startTokenRotation(sess) {
  if (sess.rotationTimer) clearInterval(sess.rotationTimer);
  rotateToken(sess);
  sess.rotationTimer = setInterval(() => {
    if (sess.active) rotateToken(sess);
  }, TOKEN_INTERVAL_MS);
}

function stopTokenRotation(sess) {
  if (sess.rotationTimer) {
    clearInterval(sess.rotationTimer);
    sess.rotationTimer = null;
  }
}

function isValidToken(sess, token) {
  if (!sess.active) return false;
  return token === sess.currentToken || token === sess.previousToken;
}

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'pulsemark-api',
    version: DEPLOY_VERSION,
    allowedOrigins,
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  const user = users.find((u) => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('pulsemark.sid', {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
    });
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/sessions', requireAuth, requireTeacher, (req, res) => {
  const title = (req.body?.title || 'Class Attendance').trim().slice(0, 80);
  const id = uuidv4();
  const sess = {
    id,
    title,
    teacherId: req.user.id,
    teacherName: req.user.name,
    createdAt: Date.now(),
    active: true,
    currentToken: null,
    previousToken: null,
    tokenIssuedAt: null,
    tokenVersion: 0,
    rotationTimer: null,
    records: [],
  };
  attendanceSessions.set(id, sess);
  startTokenRotation(sess);
  res.status(201).json({
    id: sess.id,
    title: sess.title,
    active: sess.active,
    createdAt: sess.createdAt,
    tokenIntervalMs: TOKEN_INTERVAL_MS,
  });
});

app.get('/api/sessions', requireAuth, (req, res) => {
  const list = [...attendanceSessions.values()]
    .filter((s) => (req.user.role === 'teacher' ? s.teacherId === req.user.id : s.active))
    .map((s) => ({
      id: s.id,
      title: s.title,
      teacherName: s.teacherName,
      active: s.active,
      createdAt: s.createdAt,
      attendanceCount: s.records.length,
    }))
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json({ sessions: list });
});

app.get('/api/sessions/:id', requireAuth, (req, res) => {
  const sess = attendanceSessions.get(req.params.id);
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  res.json({
    id: sess.id,
    title: sess.title,
    teacherName: sess.teacherName,
    active: sess.active,
    createdAt: sess.createdAt,
    tokenIntervalMs: TOKEN_INTERVAL_MS,
    attendanceCount: sess.records.length,
  });
});

app.get('/api/sessions/:id/token', requireAuth, requireTeacher, async (req, res) => {
  const sess = attendanceSessions.get(req.params.id);
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  if (sess.teacherId !== req.user.id) {
    return res.status(403).json({ error: 'Not your session' });
  }
  if (!sess.active) {
    return res.status(400).json({ error: 'Session is closed' });
  }
  const elapsed = Date.now() - sess.tokenIssuedAt;
  const remainingMs = Math.max(0, TOKEN_INTERVAL_MS - elapsed);
  const payload = JSON.stringify({
    sessionId: sess.id,
    token: sess.currentToken,
    v: sess.tokenVersion,
  });
  try {
    const qrDataUrl = await QRCode.toDataURL(payload, {
      width: 320,
      margin: 2,
      errorCorrectionLevel: 'M',
      color: { dark: '#14212b', light: '#ffffff' },
    });
    res.json({
      sessionId: sess.id,
      token: sess.currentToken,
      version: sess.tokenVersion,
      issuedAt: sess.tokenIssuedAt,
      expiresInMs: remainingMs,
      intervalMs: TOKEN_INTERVAL_MS,
      qrDataUrl,
    });
  } catch (err) {
    console.error('QR generate failed', err);
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

app.post('/api/sessions/:id/close', requireAuth, requireTeacher, (req, res) => {
  const sess = attendanceSessions.get(req.params.id);
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  if (sess.teacherId !== req.user.id) {
    return res.status(403).json({ error: 'Not your session' });
  }
  sess.active = false;
  stopTokenRotation(sess);
  res.json({ ok: true, attendanceCount: sess.records.length });
});

app.get('/api/sessions/:id/attendance', requireAuth, (req, res) => {
  const sess = attendanceSessions.get(req.params.id);
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  if (req.user.role === 'teacher' && sess.teacherId !== req.user.id) {
    return res.status(403).json({ error: 'Not your session' });
  }
  res.json({
    sessionId: sess.id,
    title: sess.title,
    active: sess.active,
    records: sess.records.map((r) => ({
      studentId: r.studentId,
      studentName: r.studentName,
      username: r.username,
      markedAt: r.markedAt,
    })),
  });
});

app.post('/api/attendance/mark', requireAuth, (req, res) => {
  if (req.user.role !== 'student') {
    return res.status(403).json({ error: 'Only students can mark attendance' });
  }
  const { sessionId, token } = req.body || {};
  if (!sessionId || !token) {
    return res.status(400).json({ error: 'sessionId and token required' });
  }
  const sess = attendanceSessions.get(sessionId);
  if (!sess) return res.status(404).json({ error: 'Session not found' });
  if (!sess.active) {
    return res.status(400).json({ error: 'Attendance session is closed' });
  }
  if (!isValidToken(sess, token)) {
    return res.status(400).json({
      error: 'Token expired or invalid. Scan the current QR code.',
      code: 'TOKEN_MISMATCH',
    });
  }
  const already = sess.records.find((r) => r.studentId === req.user.id);
  if (already) {
    return res.json({
      ok: true,
      alreadyMarked: true,
      message: 'Attendance already recorded',
      markedAt: already.markedAt,
      sessionTitle: sess.title,
    });
  }

  const record = {
    studentId: req.user.id,
    studentName: req.user.name,
    username: req.user.username,
    markedAt: Date.now(),
    tokenVersion: sess.tokenVersion,
  };
  sess.records.push(record);

  const apiPayload = {
    event: 'attendance.marked',
    sessionId: sess.id,
    sessionTitle: sess.title,
    studentId: req.user.id,
    studentName: req.user.name,
    username: req.user.username,
    markedAt: record.markedAt,
    tokenVersion: record.tokenVersion,
  };

  console.log('[attendance.api]', JSON.stringify(apiPayload));

  res.json({
    ok: true,
    alreadyMarked: false,
    message: 'Attendance marked successfully',
    markedAt: record.markedAt,
    sessionTitle: sess.title,
    apiPayload,
  });
});

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
  console.log(`PulseMark API on http://localhost:${PORT}`);
  console.log(`Deploy version: ${DEPLOY_VERSION}`);
  console.log(`Allowed frontends: ${allowedOrigins.join(', ')}`);
  console.log('Demo: teacher/teacher123 · student1/student123');
});
