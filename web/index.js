const express = require('express');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const app = express();
const cookieParser = require('cookie-parser');

const PORT = 8080;
const SECRET_KEY = 'your-secret-key';

const db = mysql.createConnection({
  host: 'db',
  user: 'root',
  password: 'example',
  database: 'mydb'
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/public/register.html');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    'INSERT INTO users (username, password) VALUES (?, ?)',
    [username, hashedPassword],
    (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }
      res.redirect('/login');
    }
  );
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, result) => {
    if (err || result.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    res.cookie('token', user.id, { httpOnly: true });
    res.redirect('/profile');
  });
});

app.get('/profile', (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect('/login');
  }

  db.query('SELECT * FROM users WHERE id = ?', [token], (err, result) => {
    if (err || result.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }
    const user = result[0];
    res.sendFile(__dirname + '/public/profile.html');
  });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
