const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const app = express();

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

// Security headers with CSP and HSTS
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));


// CORS configuration
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'x-api-key'],
  credentials: true
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-in-production',
  resave: false,
  saveUninitialized: true
}));

const JWT_SECRET = 'your-jwt-secret-key-change-this';
const API_KEY = 'dhc-intern-api-key-364';
const users = [];

(async () => {
  const hashedPassword = await bcrypt.hash('admin1234', 10);
  users.push({ id: 1, username: 'admin', email: 'admin@example.com', password: hashedPassword });
  logger.info('Application started');
})();

// Rate limiter for login - max 5 attempts per 15 minutes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts. Please try again after 15 minutes.',
  handler: (req, res, next, options) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).send(options.message);
  }
});

// General rate limiter for all routes
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: 'Too many requests. Please slow down.'
});

app.use(generalLimiter);

// API key middleware
function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    logger.warn(`Unauthorized API access attempt from IP: ${req.ip}`);
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  next();
}

function escapeHtml(text) {
  return validator.escape(text);
}

app.get('/', (req, res) => {
  res.send('<h1>Welcome</h1><a href="/login">Login</a> | <a href="/signup">Signup</a>');
});

app.get('/login', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = csrfToken;
  res.send(`<form method="POST" action="/login">
    <input name="username" placeholder="Username"/><br/>
    <input name="password" type="password" placeholder="Password"/><br/>
    <input type="hidden" name="_csrf" value="${csrfToken}"/>
    <button type="submit">Login</button>
  </form>`);
});

app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || validator.isEmpty(username) || validator.isEmpty(password)) {
    logger.warn('Login attempt with empty fields');
    return res.status(400).send('Username and password required');
  }
  const user = users.find(u => u.username === username);
  if (!user) {
    logger.warn(`Failed login - user not found: ${username}`);
    return res.status(401).send('Invalid credentials. <a href="/login">Try again</a>');
  }
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    logger.warn(`Failed login - wrong password for: ${username}`);
    return res.status(401).send('Invalid credentials. <a href="/login">Try again</a>');
  }
  if (req.body._csrf !== req.session.csrfToken) {
    logger.warn(`CSRF token mismatch from IP: ${req.ip}`);
    return res.status(403).send('Invalid CSRF token. Request blocked.');
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
  req.session.user = user;
  req.session.token = token;
  logger.info(`Successful login: ${username}`);
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
  if (!username || !email || !password) {
    logger.warn('Signup attempt with missing fields');
    return res.status(400).send('All fields required. <a href="/signup">Try again</a>');
  }
  if (!validator.isAlphanumeric(username) || !validator.isLength(username, { min: 3, max: 20 })) {
    logger.warn(`Invalid username format attempted: ${username}`);
    return res.status(400).send('Username must be 3-20 alphanumeric characters');
  }
  if (!validator.isEmail(email)) {
    logger.warn(`Invalid email format attempted: ${email}`);
    return res.status(400).send('Invalid email format');
  }
  if (!validator.isLength(password, { min: 6 })) {
    logger.warn('Signup attempt with short password');
    return res.status(400).send('Password must be at least 6 characters');
  }
  if (users.find(u => u.username === username)) {
    logger.warn(`Duplicate username attempted: ${username}`);
    return res.status(400).send('Username already taken');
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ id: users.length + 1, username, email, password: hashedPassword });
  logger.info(`New user signed up: ${username} (${email})`);
  res.send('Account created! <a href="/login">Login</a>');
});

// PROFILE
app.get('/profile', (req, res) => {
  if (!req.session.user) {
    logger.warn('Unauthenticated profile access attempt');
    return res.redirect('/login');
  }
  const rawName = req.query.name || req.session.user.username;
  const safeName = escapeHtml(rawName);
  res.send(`<h1>Welcome, ${safeName}!</h1><a href="/logout">Logout</a>`);
});

// PROTECTED API ENDPOINT (requires API key)
app.get('/api/search', (req, res) => {
  const query = req.query.q;
  const sql = "SELECT * FROM products WHERE name = ?";
  db.all(sql, [query], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/logout', (req, res) => {
  logger.info(`User logged out: ${req.session.user ? req.session.user.username : 'unknown'}`);
  req.session.destroy();
  res.redirect('/');
});
// INTENTIONALLY VULNERABLE endpoint for SQLi demo (Week 5)
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run("CREATE TABLE products (id INT, name TEXT, price TEXT)");
  db.run("INSERT INTO products VALUES (1, 'Widget', '$10')");
  db.run("INSERT INTO products VALUES (2, 'Gadget', '$20')");
  db.run("INSERT INTO products VALUES (3, 'Doohickey', '$30')");
});

app.get('/api/search', (req, res) => {
  const query = req.query.q;
  const sql = "SELECT * FROM products WHERE name = '" + query + "'";
  db.all(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.listen(3000, () => console.log('App running at http://localhost:3000'));
