// routes/api.js
// Sample API endpoints to demonstrate monitoring and protection

const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/security');
const crypto = require('crypto');

/**
 * @route   GET /api/test/public
 * @desc    Public endpoint - no auth required
 */
router.get('/public', (req, res) => {
  res.json({
    success: true,
    message: 'This is a public endpoint',
    timestamp: new Date(),
    data: { server: 'API Sentinel', version: '1.0.0' }
  });
});

/**
 * @route   GET /api/test/protected
 * @desc    Protected endpoint - requires JWT
 */
router.get('/protected', protect, (req, res) => {
  res.json({
    success: true,
    message: 'You have access to this protected resource!',
    user: req.user.username,
    role: req.user.role,
    data: { secret: 'Confidential enterprise data here' }
  });
});

/**
 * @route   POST /api/test/data-integrity
 * @desc    Demonstrates data hashing for integrity
 */
router.post('/data-integrity', protect, (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res.status(400).json({ success: false, message: 'Please provide data field' });
  }

  // Hash the data using SHA-256 to demonstrate integrity checking
  const hash = crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
  const hmac = crypto.createHmac('sha256', process.env.JWT_SECRET)
                     .update(JSON.stringify(data))
                     .digest('hex');

  res.json({
    success: true,
    message: 'Data integrity verified',
    original: data,
    sha256Hash: hash,
    hmacSignature: hmac,
    timestamp: new Date(),
    note: 'Store the HMAC with data. If data changes, HMAC wont match = tampered!'
  });
});

/**
 * @route   GET /api/test/health
 * @desc    System health check endpoint
 */
router.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'operational',
    uptime: Math.floor(process.uptime()) + 's',
    memory: process.memoryUsage(),
    timestamp: new Date()
  });
});

module.exports = router;
