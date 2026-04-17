// routes/auth.js
const express = require('express');
const router = express.Router();
const { register, login, getMe } = require('../controllers/authController');
const { protect } = require('../middleware/security');

// Public routes
router.post('/register', register);
router.post('/login', login);

// Protected route - requires valid JWT
router.get('/me', protect, getMe);

module.exports = router;
