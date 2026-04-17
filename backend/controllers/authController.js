// controllers/authController.js
// Handles user registration, login, and profile management

const User = require('../models/User');
const Log = require('../models/Log');
const { trackFailedLogin, resetFailedLogins, autoBlockIP } = require('../utils/anomalyDetector');

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
const register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    const ip = req.ip || 'unknown';

    // Basic validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide username, email, and password'
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or username already exists'
      });
    }

    // Only allow admin role if specifically set (prevent privilege escalation)
    const userRole = role === 'admin' ? 'admin' : 'user';

    const user = await User.create({ username, email, password, role: userRole });

    // Log the registration
    await Log.create({
      type: 'auth',
      method: 'POST',
      endpoint: '/api/auth/register',
      ip,
      statusCode: 201,
      message: `New user registered: ${username} (${userRole})`,
      userId: user._id,
      isThreat: false,
      severity: 'low'
    });

    const token = user.getSignedJwtToken();

    res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Register error:', error.message);
    res.status(500).json({ success: false, message: 'Server error during registration' });
  }
};

/**
 * @route   POST /api/auth/login
 * @desc    Login user and return JWT
 * @access  Public
 */
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = req.ip || 'unknown';

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email and password'
      });
    }

    // Find user and include password field
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      // Track failed login attempt
      const failCheck = trackFailedLogin(ip);
      if (failCheck.shouldBlock) {
        await autoBlockIP(ip, failCheck.reason);
      }

      await Log.create({
        type: 'auth',
        method: 'POST',
        endpoint: '/api/auth/login',
        ip,
        statusCode: 401,
        message: `❌ Failed login: Email not found - ${email}`,
        isThreat: true,
        severity: 'medium'
      });

      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check if user is blocked
    if (user.isBlocked && user.blockedUntil > new Date()) {
      return res.status(403).json({
        success: false,
        message: 'Account blocked due to too many failed attempts',
        blockedUntil: user.blockedUntil
      });
    }

    // Verify password
    const isMatch = await user.matchPassword(password);

    if (!isMatch) {
      // Increment failed attempts
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      user.lastFailedLogin = new Date();

      // SELF-HEALING: Block user account after too many failures
      if (user.failedLoginAttempts >= parseInt(process.env.FAILED_LOGIN_THRESHOLD || 5)) {
        user.isBlocked = true;
        user.blockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 min
        
        await Log.create({
          type: 'block',
          method: 'SYSTEM',
          endpoint: '/api/auth/login',
          ip,
          statusCode: 403,
          message: `🔒 USER ACCOUNT LOCKED: ${user.email} after ${user.failedLoginAttempts} failed attempts`,
          userId: user._id,
          isThreat: true,
          severity: 'critical'
        });
      }

      await user.save();

      // Also track on IP level
      const failCheck = trackFailedLogin(ip);
      if (failCheck.shouldBlock) {
        await autoBlockIP(ip, failCheck.reason);
      }

      await Log.create({
        type: 'auth',
        method: 'POST',
        endpoint: '/api/auth/login',
        ip,
        statusCode: 401,
        message: `❌ Wrong password for: ${email} (attempt #${user.failedLoginAttempts})`,
        userId: user._id,
        isThreat: true,
        severity: 'medium'
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        attemptsRemaining: Math.max(0, 5 - user.failedLoginAttempts)
      });
    }

    // SUCCESS: Reset failed login counter
    user.failedLoginAttempts = 0;
    user.isBlocked = false;
    await user.save();
    resetFailedLogins(ip);

    await Log.create({
      type: 'auth',
      method: 'POST',
      endpoint: '/api/auth/login',
      ip,
      statusCode: 200,
      message: `✅ Successful login: ${user.username}`,
      userId: user._id,
      isThreat: false,
      severity: 'low'
    });

    const token = user.getSignedJwtToken();

    res.status(200).json({
      success: true,
      message: `Welcome back, ${user.username}!`,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
};

/**
 * @route   GET /api/auth/me
 * @desc    Get current logged-in user profile
 * @access  Private
 */
const getMe = async (req, res) => {
  res.status(200).json({
    success: true,
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
      createdAt: req.user.createdAt
    }
  });
};

module.exports = { register, login, getMe };
