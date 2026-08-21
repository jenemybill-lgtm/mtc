require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// --- DATABASE MODELS ---
const userSchema = new mongoose.Schema({
  companyName: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  phoneNumber: { type: String, required: true }, // Backup for password recovery
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const companyDataSchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true },
  payload: mongoose.Schema.Types.Mixed,
  lastUpdated: { type: Date, default: Date.now }
}, { strict: false });
const CompanyData = mongoose.model('CompanyData', companyDataSchema);

// --- AUTHENTICATION ROUTES ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { companyName, password, phoneNumber } = req.body;
    if (!companyName || !password || !phoneNumber) {
      return res.status(400).json({ message: 'Παρακαλώ συμπληρώστε όλα τα πεδία' });
    }

    let user = await User.findOne({ companyName });
    if (user) return res.status(400).json({ message: 'Η εταιρεία υπάρχει ήδη' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ companyName, password: hashedPassword, phoneNumber });
    await user.save();

    const token = jwt.sign({ user: { id: user.id } }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, companyName });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { companyName, password } = req.body;
    const user = await User.findOne({ companyName });
    if (!user) return res.status(400).json({ message: 'Λάθος στοιχεία σύνδεσης' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Λάθος στοιχεία σύνδεσης' });

    const token = jwt.sign({ user: { id: user.id } }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, companyName });
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Fallback login with Phone Number
app.post('/api/auth/login-phone', async (req, res) => {
  try {
    const { companyName, phoneNumber } = req.body;
    const user = await User.findOne({ companyName, phoneNumber });
    if (!user) return res.status(400).json({ message: 'Λάθος όνομα εταιρείας ή τηλέφωνο' });

    const token = jwt.sign({ user: { id: user.id } }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, companyName });
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// --- SYNC ROUTES ---
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

app.post('/api/sync/upload', authMiddleware, async (req, res) => {
  try {
    await CompanyData.findOneAndUpdate(
      { companyId: req.user.id },
      { payload: req.body.data, lastUpdated: new Date() },
      { upsert: true }
    );
    res.json({ message: 'Συγχρονισμός επιτυχής' });
  } catch (err) {
    res.status(500).send('Server error during upload');
  }
});

app.get('/api/sync/download', authMiddleware, async (req, res) => {
  try {
    const data = await CompanyData.findOne({ companyId: req.user.id });
    res.json(data ? data.payload : { projects: [] });
  } catch (err) {
    res.status(500).send('Server error during download');
  }
});

app.get('/', (req, res) => res.send('MTC ERP API IS LIVE'));

// --- SERVER START ---
const PORT = process.env.PORT || 5000;
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => console.error('Database connection error:', err));
