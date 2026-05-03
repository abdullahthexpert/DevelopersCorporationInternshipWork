const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'weakpassword', resave: false, saveUninitialized: true }));

// Fake user database
const users = [{ id: 1, username: 'admin', password: '1234' }];

app.get('/', (req, res) => {
  res.send('<h1>Welcome</h1><a href="/login">Login</a> | <a href="/signup">Signup</a>');
});

// Vulnerable login - no input sanitization
app.get('/login', (req, res) => {
  res.send(`<form method="POST" action="/login">
    <input name="username" placeholder="Username"/><br/>
    <input name="password" type="password" placeholder="Password"/><br/>
    <button type="submit">Login</button>
  </form>`);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (user) {
    req.session.user = user;
    res.redirect('/profile');
  } else {
    res.send('Invalid credentials. <a href="/login">Try again</a>');
  }
});

// Vulnerable signup - no validation
app.get('/signup', (req, res) => {
  res.send(`<form method="POST" action="/signup">
    <input name="username" placeholder="Username"/><br/>
    <input name="password" type="password" placeholder="Password"/><br/>
    <button type="submit">Signup</button>
  </form>`);
});

app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  users.push({ id: users.length + 1, username, password });
  res.send('Account created! <a href="/login">Login</a>');
});

// Vulnerable profile - XSS possible
app.get('/profile', (req, res) => {
  const name = req.query.name || (req.session.user ? req.session.user.username : 'Guest');
  res.send(`<h1>Welcome, ${name}!</h1><a href="/logout">Logout</a>`);
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(3000, () => console.log('App running at http://localhost:3000'));

