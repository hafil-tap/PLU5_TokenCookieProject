// server.js
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ───────────────────────────────────────────────────────────
// In-memory data (seeded). Passwords are hashed at start-up.
// ───────────────────────────────────────────────────────────
const users = [
  { id: 1, email: 'admin@test.com', password: '', firstName: 'Admin', role: 'admin' },
  { id: 2, email: 'user@test.com',  password: '', firstName: 'User',  role: 'user'  }
];

const tasks = [
  { id: 1, userId: 1, title: 'Admin Task', description: 'Admin only task', completed: false, createdAt: new Date().toISOString() },
  { id: 2, userId: 2, title: 'User Task',  description: 'Regular user task', completed: false, createdAt: new Date().toISOString() }
];

// Hash seed passwords once (admin123 / user123)
users[0].password = bcrypt.hashSync('admin123', 10);
users[1].password = bcrypt.hashSync('user123', 10);

// ───────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'dev_fallback';
const isProd = process.env.NODE_ENV === 'production';

function signToken(user) {
  // keep payload small
  return jwt.sign(
    { id: user.id, email: user.email, firstName: user.firstName, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

function setAuthCookie(res, token) {
  res.cookie('authToken', token, {
    httpOnly: true,
    secure: isProd,            // true in production (HTTPS)
    sameSite: 'strict',
    maxAge: 60 * 60 * 1000,    // 1 hour
    path: '/',
  });
}

function clearAuthCookie(res) {
  res.clearCookie('authToken', { httpOnly: true, sameSite: 'strict', secure: isProd, path: '/' });
}

// ───────────────────────────────────────────────────────────
// Auth middleware
// ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ error: 'Missing auth token' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, firstName, role }
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (req.user.role !== role) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

// ───────────────────────────────────────────────────────────
// Auth routes
// ───────────────────────────────────────────────────────────

// Register: {email, password, firstName, role?}
app.post('/register', async (req, res) => {
  const { email, password, firstName, role } = req.body;
  if (!email || !password || !firstName) {
    return res.status(400).json({ error: 'email, password, firstName are required' });
  }
  const exists = users.find(u => u.email === email);
  if (exists) return res.status(409).json({ error: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: users.length ? Math.max(...users.map(u => u.id)) + 1 : 1,
    email,
    password: hashed,
    firstName,
    role: role === 'admin' ? 'admin' : 'user',
  };
  users.push(newUser);

  // Auto-login after register
  const token = signToken(newUser);
  setAuthCookie(res, token);
  res.status(201).json({ message: 'Registered', user: { id: newUser.id, email, firstName, role: newUser.role } });
});

// Login: {email, password}
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = signToken(user);
  setAuthCookie(res, token);
  res.json({ message: 'Logged in' });
});

// Logout
app.post('/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ message: 'Logged out' });
});

// Current profile (protected)
app.get('/profile', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ───────────────────────────────────────────────────────────
// Task routes (user-only visibility)
// ───────────────────────────────────────────────────────────

// Get my tasks
app.get('/tasks', requireAuth, (req, res) => {
  const myTasks = tasks.filter(t => t.userId === req.user.id);
  res.json({ tasks: myTasks });
});

// Create task: {title, description}
app.post('/tasks', requireAuth, (req, res) => {
  const { title, description } = req.body;
  if (!title) return res.status(400).json({ error: 'title is required' });

  const newTask = {
    id: tasks.length ? Math.max(...tasks.map(t => t.id)) + 1 : 1,
    userId: req.user.id,
    title,
    description: description || '',
    completed: false,
    createdAt: new Date().toISOString()
  };
  tasks.push(newTask);
  res.status(201).json({ task: newTask });
});

// Delete my task
app.delete('/tasks/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const idx = tasks.findIndex(t => t.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Task not found' });
  if (tasks[idx].userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

  const removed = tasks.splice(idx, 1)[0];
  res.json({ deleted: removed });
});

// ───────────────────────────────────────────────────────────
// Admin routes
// ───────────────────────────────────────────────────────────
app.get('/admin/users', requireAuth, requireRole('admin'), (req, res) => {
  const slim = users.map(u => ({ id: u.id, email: u.email, firstName: u.firstName, role: u.role }));
  res.json({ users: slim });
});

app.get('/admin/tasks', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ tasks });
});

// ───────────────────────────────────────────────────────────
// Start server
// ───────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
  console.log(`Seed logins -> admin@test.com/admin123, user@test.com/user123`);
});
