const express = require('express');
const app = express();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const port = process.env.PORT || 3001;
const mongourl = process.env.MONGO_URL;

// --- Middleware setup ---
app.set('view engine', 'ejs');
app.set('views', 'views');

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// --- Connect MongoDB ---
mongoose.connect(mongourl)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch((err) => console.log(err));

// --- Schema ---
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true }, // fixed typo
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const Users = mongoose.model('Users', UserSchema);

app.get('/', (req, res) => {
  res.redirect('/login'); // or res.render('home');
});

// --- Routes ---
app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

// --- Register ---
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    await Users.create({ username, email, password: hashed });
    res.redirect('/login');
  } catch (err) {
    console.log('❌ Registration Error:', err);
    res.send('Registration failed');
  }
});

// --- Login ---
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await Users.findOne({ email: email }); // fixed: use findOne

    if (!user) return res.status(401).send('No user found');
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send('Invalid password');

    // ✅ Create JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    // ✅ Store token in cookie
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/dashboard');
  } catch (err) {
    console.log('❌ Login Error:', err);
    res.send('Login failed');
  }
});

// --- Middleware to verify JWT ---
function isVerify(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decode = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decode;
    next();
  } catch (err) {
    res.redirect('/login');
  }
}

// --- Dashboard (Protected Route) ---
app.get('/dashboard', isVerify, async (req, res) => {
  const user = await Users.findById(req.user.id); // fixed: get from DB
  res.render('dashboard', { user });
});

// --- Logout ---
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// --- Start Server ---
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
