// middleware/security.js
// Main security middleware - runs on EVERY request

const Log = require('../models/Log');
const {
  trackRequest,
  autoBlockIP,
  isIPBlocked,
  detectInjection
} = require('../utils/anomalyDetector');

/**
 * REQUEST LOGGER MIDDLEWARE
 * Logs every API request to the database
 */
const requestLogger = (io) => async (req, res, next) => {
  const startTime = Date.now();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';

  // After response is sent, log the details
  res.on('finish', async () => {
    const responseTime = Date.now() - startTime;
    const isThreat = res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 429;

    try {
      const log = await Log.create({
        type: 'request',
        method: req.method,
        endpoint: req.originalUrl,
        ip,
        statusCode: res.statusCode,
        responseTime,
        userAgent: req.headers['user-agent'] || 'Unknown',
        userId: req.user ? req.user.id : null,
        message: `${req.method} ${req.originalUrl} → ${res.statusCode} (${responseTime}ms)`,
        isThreat,
        severity: isThreat ? 'medium' : 'low',
        details: {
          query: req.query,
          referer: req.headers.referer || null
        }
      });

      // Emit real-time log to dashboard
      if (io) {
        io.emit('new-log', {
          ...log.toObject(),
          timestamp: new Date()
        });
      }
    } catch (err) {
      // Don't crash the server just because logging failed
      console.error('Logging error:', err.message);
    }
  });

  next();
};

/**
 * ANOMALY DETECTION MIDDLEWARE
 * Checks every incoming request for suspicious behavior
 */
const anomalyDetector = (io) => async (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';

  // STEP 1: Check if IP is already blocked
  const blockStatus = await isIPBlocked(ip);
  if (blockStatus.blocked) {
    await Log.create({
      type: 'anomaly',
      method: req.method,
      endpoint: req.originalUrl,
      ip,
      statusCode: 403,
      message: `🚫 BLOCKED IP attempt: ${ip} tried to access ${req.originalUrl}`,
      isThreat: true,
      severity: 'high',
      details: { blockedUntil: blockStatus.until, reason: blockStatus.reason }
    });

    return res.status(403).json({
      success: false,
      message: 'Access denied. Your IP has been blocked due to suspicious activity.',
      blockedUntil: blockStatus.until
    });
  }

  // STEP 2: Rate limit check per IP
  const rateCheck = trackRequest(ip);
  if (rateCheck.suspicious) {
    // AUTO-BLOCK the IP
    await autoBlockIP(ip, rateCheck.reason, io);

    if (io) {
      io.emit('security-alert', {
        type: 'rate-limit-exceeded',
        ip,
        reason: rateCheck.reason,
        timestamp: new Date()
      });
    }

    await Log.create({
      type: 'anomaly',
      method: req.method,
      endpoint: req.originalUrl,
      ip,
      statusCode: 429,
      message: `⚡ RATE LIMIT: ${ip} exceeded request threshold`,
      isThreat: true,
      severity: 'high',
      details: { reason: rateCheck.reason }
    });

    return res.status(429).json({
      success: false,
      message: 'Too many requests. Your IP has been temporarily blocked.',
      retryAfter: `${process.env.BLOCK_DURATION_MINUTES || 30} minutes`
    });
  }

  // STEP 3: Check for injection attacks in request body/query
  const hasInjection = detectInjection(req.body) || detectInjection(req.query);
  if (hasInjection) {
    await autoBlockIP(ip, 'Injection attack pattern detected', io);

    await Log.create({
      type: 'anomaly',
      method: req.method,
      endpoint: req.originalUrl,
      ip,
      statusCode: 400,
      message: `💉 INJECTION DETECTED: Malicious payload from ${ip}`,
      isThreat: true,
      severity: 'critical',
      details: {
        body: JSON.stringify(req.body).substring(0, 200), // Only store first 200 chars
        query: req.query
      }
    });

    return res.status(400).json({
      success: false,
      message: 'Malicious input detected and blocked.'
    });
  }

  next();
};

/**
 * JWT AUTHENTICATION MIDDLEWARE
 * Protects routes that require login
 */
const protect = async (req, res, next) => {
  let token;

  // Check Authorization header for Bearer token
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Not authorized. Please login first.'
    });
  }

  try {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const User = require('../models/User');
    req.user = await User.findById(decoded.id);

    if (!req.user) {
      return res.status(401).json({ success: false, message: 'User not found.' });
    }

    // Check if user is blocked
    if (req.user.isBlocked && req.user.blockedUntil > new Date()) {
      return res.status(403).json({
        success: false,
        message: 'Account temporarily blocked due to suspicious activity.',
        blockedUntil: req.user.blockedUntil
      });
    }

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token. Please login again.'
    });
  }
};

/**
 * ROLE-BASED ACCESS CONTROL
 * Usage: authorize('admin') or authorize('admin', 'user')
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. This route requires ${roles.join(' or ')} role.`
      });
    }
    next();
  };
};

module.exports = { requestLogger, anomalyDetector, protect, authorize };
