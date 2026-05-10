const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');

const app = express();

// Security: secure HTTP headers
app.use(helmet());

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ 
  secret: process.env.SESSION_SECRET || 'change-this-in-production', 
  resave: false, 
  saveUninitialized: true 
}));

// Secret for JWT (in real apps, use environment variables)
const JWT_SECRET = 'your-jwt-secret-key-change-this';

// Fake user database - passwords now hashed
const users = [];

// Pre-hash the admin password on startup
(async () => {
  const hashedPassword = await bcrypt.hash('admin1234', 10);
  users.push({ id: 1, username: 'admin', email: 'admin@example.com', password: hashedPassword });
})();

// Helper: escape HTML to prevent XSS
function escapeHtml(text) {
  return validator.escape(text);
}

app.get('/', (req, res) => {
  res.send('<h1>Welcome</h1><a href="/login">Login</a> | <a href="/signup">Signup</a>');
});

// LOGIN
app.get('/login', (req, res) => {
  res.send(`<form method="POST" action="/login">
    <input name="username" placeholder="Username"/><br/>
    <input name="password" type="password" placeholder="Password"/><br/>
    <button type="submit">Login</button>
  </form>`);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Validate inputs exist and are clean
  if (!username || !password || validator.isEmpty(username) || validator.isEmpty(password)) {
    return res.status(400).send('Username and password required');
  }

  // Find user
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).send('Invalid credentials. <a href="/login">Try again</a>');
  }

  // Compare hashed password
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).send('Invalid credentials. <a href="/login">Try again</a>');
  }

  // Generate JWT token
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
  req.session.user = user;
  req.session.token = token;
  res.redirect('/profile');
});

// SIGNUP
app.get('/signup', (req, res) => {
  res.send(`<form method="POST" action="/signup">
    <input name="username" placeholder="Username"/><br/>
    <input name="email" placeholder="Email"/><br/>
    <input name="password" type="password" placeholder="Password (min 6 chars)"/><br/>
    <button type="submit">Signup</button>
  </form>`);
});

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  // Input validation
  if (!username || !email || !password) {
    return res.status(400).send('All fields required. <a href="/signup">Try again</a>');
  }
  if (!validator.isAlphanumeric(username) || !validator.isLength(username, { min: 3, max: 20 })) {
    return res.status(400).send('Username must be 3-20 alphanumeric characters');
  }
  if (!validator.isEmail(email)) {
    return res.status(400).send('Invalid email format');
  }
  if (!validator.isLength(password, { min: 6 })) {
    return res.status(400).send('Password must be at least 6 characters');
  }

  // Check duplicate username
  if (users.find(u => u.username === username)) {
    return res.status(400).send('Username already taken');
  }

  // Hash password before storing
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ 
    id: users.length + 1, 
    username, 
    email, 
    password: hashedPassword 
  });

  res.send('Account created! <a href="/login">Login</a>');
});

// PROFILE - XSS fixed by escaping output
app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  const rawName = req.query.name || req.session.user.username;
  const safeName = escapeHtml(rawName); // <-- prevents XSS
  res.send(`<h1>Welcome, ${safeName}!</h1><a href="/logout">Logout</a>`);
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(3000, () => console.log('App running at http://localhost:3000'));
