const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

const db = new sqlite3.Database('./database.db');

// Initialize database tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS driver_profiles (
    userId INTEGER UNIQUE,
    name TEXT,
    licenseNumber TEXT,
    experience INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS company_profiles (
    userId INTEGER UNIQUE,
    companyName TEXT,
    location TEXT,
    fleetSize INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    driverId INTEGER,
    companyId INTEGER,
    rating INTEGER,
    comment TEXT,
    createdAt TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    companyId INTEGER,
    title TEXT,
    description TEXT,
    pay TEXT,
    location TEXT,
    createdAt TEXT
  )`);
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token is required');
  try {
    const decoded = jwt.verify(token, 'secret');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send('Invalid token');
  }
};

// Register
app.post('/api/register', (req, res) => {
  const { email, password, role } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);
  db.run(`INSERT INTO users (email, password, role) VALUES (?, ?, ?)`, [email, hashedPassword, role], function(err) {
    if (err) return res.status(500).send('Error registering user');
    res.status(201).send({ id: this.lastID });
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err || !user) return res.status(404).send('User not found');
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) return res.status(401).send('Invalid password');
    const token = jwt.sign({ id: user.id, role: user.role }, 'secret', { expiresIn: '1h' });
    res.status(200).send({ token, role: user.role });
  });
});

// Get company profile
app.get('/api/companies/:id', (req, res) => {
  db.get(`SELECT * FROM company_profiles WHERE userId = ?`, [req.params.id], (err, profile) => {
    if (err || !profile) return res.status(404).send('Company not found');
    res.status(200).send(profile);
  });
});

// Submit review
app.post('/api/reviews', verifyToken, (req, res) => {
  if (req.user.role !== 'driver') return res.status(403).send('Only drivers can submit reviews');
  const { companyId, rating, comment } = req.body;
  const createdAt = new Date().toISOString();
  db.run(`INSERT INTO reviews (driverId, companyId, rating, comment, createdAt) VALUES (?, ?, ?, ?, ?)`, [req.user.id, companyId, rating, comment, createdAt], function(err) {
    if (err) return res.status(500).send('Error submitting review');
    res.status(201).send({ id: this.lastID });
  });
});

// Get reviews for a company
app.get('/api/reviews', (req, res) => {
  const { companyId } = req.query;
  db.all(`SELECT * FROM reviews WHERE companyId = ?`, [companyId], (err, reviews) => {
    if (err) return res.status(500).send('Error fetching reviews');
    res.status(200).send(reviews);
  });
});

// Post job
app.post('/api/jobs', verifyToken, (req, res) => {
  if (req.user.role !== 'company') return res.status(403).send('Only companies can post jobs');
  const { title, description, pay, location } = req.body;
  const createdAt = new Date().toISOString();
  db.run(`INSERT INTO jobs (companyId, title, description, pay, location, createdAt) VALUES (?, ?, ?, ?, ?, ?)`, [req.user.id, title, description, pay, location, createdAt], function(err) {
    if (err) return res.status(500).send('Error posting job');
    res.status(201).send({ id: this.lastID });
  });
});

// Get all jobs
app.get('/api/jobs', (req, res) => {
  db.all(`SELECT * FROM jobs`, [], (err, jobs) => {
    if (err) return res.status(500).send('Error fetching jobs');
    res.status(200).send(jobs);
  });
});

// Delete review (admin only)
app.delete('/api/reviews/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Only admins can delete reviews');
  db.run(`DELETE FROM reviews WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).send('Error deleting review');
    res.status(200).send('Review deleted');
  });
});

// Delete job (admin only)
app.delete('/api/jobs/:id', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Only admins can delete jobs');
  db.run(`DELETE FROM jobs WHERE id = ?`, [req.params.id], (err) => {
    if (err) return res.status(500).send('Error deleting job');
    res.status(200).send('Job deleted');
  });
});

app.listen(3000, () => console.log('Server running on port 3000'));
