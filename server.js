const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');

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

// Security: secure HTTP headers
app.use(helmet());

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ 
  secret: process.env.SESSION_SECRET || 'change-this-in-production', 
  resave: false, 
  saveUninitialized: true 
}));

const JWT_SECRET = 'your-jwt-secret-key-change-this';

const users = [];

(async () => {
  const hashedPassword = await bcrypt.hash('admin1234', 10);
  users.push({ id: 1, username: 'admin', email: 'admin@example.com', password: hashedPassword });
  logger.info('Application started');
})();

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

app.get('/logout', (req, res) => {
  logger.info(`User logged out: ${req.session.user ? req.session.user.username : 'unknown'}`);
  req.session.destroy();
  res.redirect('/');
});

app.listen(3000, () => console.log('App running at http://localhost:3000'));
