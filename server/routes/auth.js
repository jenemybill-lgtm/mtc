const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// @route   POST api/auth/register
// @desc    Register a new company
router.post('/register', async (req, res) => {
  try {
    const { companyName, password } = req.body;

    let user = await User.findOne({ companyName });
    if (user) return res.status(400).json({ message: 'Η εταιρεία υπάρχει ήδη' });

    user = new User({ companyName, password });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    await user.save();

    const payload = { user: { id: user.id } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' }, (err, token) => {
      if (err) throw err;
      res.json({ token, companyName: user.companyName });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

// @route   POST api/auth/login
// @desc    Authenticate company & get token
router.post('/login', async (req, res) => {
  try {
    const { companyName, password } = req.body;

    const user = await User.findOne({ companyName });
    if (!user) return res.status(400).json({ message: 'Λάθος στοιχεία σύνδεσης' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Λάθος στοιχεία σύνδεσης' });

    const payload = { user: { id: user.id } };
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '30d' }, (err, token) => {
      if (err) throw err;
      res.json({ token, companyName: user.companyName });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});

module.exports = router;
