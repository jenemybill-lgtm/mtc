const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// Middleware to verify JWT
const auth = (req, res, next) => {
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

const CompanyDataSchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true },
  payload: mongoose.Schema.Types.Mixed,
  lastUpdated: { type: Date, default: Date.now }
}, { strict: false });

const CompanyData = mongoose.models.CompanyData || mongoose.model('CompanyData', CompanyDataSchema);

// @route   POST api/sync/upload
// @desc    Sync data from mobile to cloud
router.post('/upload', auth, async (req, res) => {
  try {
    const { data } = req.body;
    const companyId = req.user.id;

    await CompanyData.findOneAndUpdate(
        { companyId },
        { payload: data, lastUpdated: new Date() },
        { upsert: true }
    );

    res.json({ message: 'Συγχρονισμός επιτυχής' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error during upload');
  }
});

// @route   GET api/sync/download
// @desc    Pull data from cloud to mobile
router.get('/download', auth, async (req, res) => {
    try {
      const companyId = req.user.id;
      const data = await CompanyData.findOne({ companyId });
      if (!data) return res.json({ projects: [] });

      res.json(data.payload);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error during download');
    }
  });

module.exports = router;
