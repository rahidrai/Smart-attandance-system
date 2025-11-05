const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Use env var in production

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files (e.g., your HTML)

// In-memory storage (mock database)
let users = []; // { id, username, password, role }
let attendance = []; // { date, time, student, id, category, status }

// Middleware to verify JWT
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Serve the HTML file at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register endpoint (only for students in this mock)
app.post('/register', async (req, res) => {
  const { fullname, password } = req.body;
  if (!fullname || !password) return res.status(400).json({ error: 'Full name and password required' });
  
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: users.length + 1, username: fullname, password: hashedPassword, role: 'student' };
  users.push(user);
  res.json({ message: 'Registration successful' });
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { role, userId, password } = req.body;
  const user = users.find(u => u.username === userId && u.role === role);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
  res.json({ token });
});

// Mark attendance (students only)
app.post('/attendance', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Access denied' });
  
  const { category } = req.body;
  const now = new Date();
  const record = {
    date: now.toISOString().split('T')[0],
    time: now.toTimeString().split(' ')[0],
    student: req.user.username,
    id: req.user.id,
    category,
    status: 'Logged'
  };
  attendance.push(record);
  res.json({ message: 'Attendance marked', record });
});

// Get attendance records
app.get('/attendance', authenticate, (req, res) => {
  let records = attendance;
  if (req.user.role === 'student') {
    records = records.filter(r => r.student === req.user.username);
  }
  // Apply filters (from query params)
  const { date, category } = req.query;
  if (date) records = records.filter(r => r.date === date);
  if (category) records = records.filter(r => r.category === category);
  res.json(records);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});