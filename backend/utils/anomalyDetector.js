// utils/anomalyDetector.js
// Core anomaly detection engine using rule-based logic (no ML needed)

const BlockedIP = require('../models/BlockedIP');
const Log = require('../models/Log');

// In-memory store for tracking requests per IP (resets on server restart)
// For production, use Redis instead
const requestTracker = new Map(); // ip -> { count, firstRequest, failedLogins }

// =============================================
// RULE 1: Rate Limiting per IP
// If an IP makes too many requests in 1 minute → mark as suspicious
// =============================================
const REQUESTS_PER_MINUTE = parseInt(process.env.REQUESTS_PER_MINUTE_THRESHOLD) || 30;
const FAILED_LOGIN_LIMIT = parseInt(process.env.FAILED_LOGIN_THRESHOLD) || 5;
const BLOCK_DURATION = parseInt(process.env.BLOCK_DURATION_MINUTES) || 30;

/**
 * Track a request from an IP address
 * Returns { suspicious: bool, reason: string }
 */
const trackRequest = (ip) => {
  const now = Date.now();
  const oneMinute = 60 * 1000;

  if (!requestTracker.has(ip)) {
    requestTracker.set(ip, {
      count: 1,
      firstRequest: now,
      failedLogins: 0,
      lastFailedLogin: null
    });
    return { suspicious: false };
  }

  const data = requestTracker.get(ip);

  // Reset counter if window has passed
  if (now - data.firstRequest > oneMinute) {
    data.count = 1;
    data.firstRequest = now;
    requestTracker.set(ip, data);
    return { suspicious: false };
  }

  // Increment request count
  data.count++;
  requestTracker.set(ip, data);

  // RULE 1: Too many requests
  if (data.count > REQUESTS_PER_MINUTE) {
    return {
      suspicious: true,
      reason: `Rate limit exceeded: ${data.count} requests in 1 minute (limit: ${REQUESTS_PER_MINUTE})`
    };
  }

  return { suspicious: false };
};

/**
 * Track a failed login attempt for an IP
 * Returns { shouldBlock: bool }
 */
const trackFailedLogin = (ip) => {
  const now = Date.now();
  
  if (!requestTracker.has(ip)) {
    requestTracker.set(ip, { count: 0, firstRequest: now, failedLogins: 1, lastFailedLogin: now });
  } else {
    const data = requestTracker.get(ip);
    data.failedLogins = (data.failedLogins || 0) + 1;
    data.lastFailedLogin = now;
    requestTracker.set(ip, data);
  }

  const data = requestTracker.get(ip);

  // RULE 2: Too many failed logins
  if (data.failedLogins >= FAILED_LOGIN_LIMIT) {
    return {
      shouldBlock: true,
      reason: `${data.failedLogins} consecutive failed login attempts`
    };
  }

  return { shouldBlock: false };
};

/**
 * Reset failed login counter after successful login
 */
const resetFailedLogins = (ip) => {
  if (requestTracker.has(ip)) {
    const data = requestTracker.get(ip);
    data.failedLogins = 0;
    requestTracker.set(ip, data);
  }
};

/**
 * SELF-HEALING: Auto-block a suspicious IP
 * Saves to DB and logs the action
 */
const autoBlockIP = async (ip, reason, io = null) => {
  try {
    const blockedUntil = new Date(Date.now() + BLOCK_DURATION * 60 * 1000);

    // Upsert: create or update the block record
    await BlockedIP.findOneAndUpdate(
      { ip },
      {
        ip,
        reason,
        blockedUntil,
        isActive: true,
        $inc: { flagCount: 1 }
      },
      { upsert: true, new: true }
    );

    // Log the self-healing action
    const log = await Log.create({
      type: 'block',
      method: 'SYSTEM',
      endpoint: '/self-heal',
      ip,
      message: `🛡️ AUTO-BLOCKED: ${ip} | Reason: ${reason} | Until: ${blockedUntil.toISOString()}`,
      isThreat: true,
      severity: 'high',
      details: { reason, blockedUntil, autoBlocked: true }
    });

    // Emit real-time alert via Socket.io if available
    if (io) {
      io.emit('security-alert', {
        type: 'ip-blocked',
        ip,
        reason,
        blockedUntil,
        timestamp: new Date()
      });
    }

    console.log(`🚫 IP AUTO-BLOCKED: ${ip} | ${reason}`);
    return true;
  } catch (error) {
    console.error('Auto-block error:', error.message);
    return false;
  }
};

/**
 * Check if an IP is currently blocked
 */
const isIPBlocked = async (ip) => {
  try {
    const blocked = await BlockedIP.findOne({ ip, isActive: true });
    if (!blocked) return { blocked: false };

    // SELF-HEALING: Auto-unblock if time has expired
    if (new Date() > blocked.blockedUntil) {
      await BlockedIP.findOneAndUpdate({ ip }, { isActive: false });
      
      await Log.create({
        type: 'heal',
        method: 'SYSTEM',
        endpoint: '/self-heal',
        ip,
        message: `✅ AUTO-UNBLOCKED: ${ip} | Block period expired`,
        isThreat: false,
        severity: 'low',
        details: { autoHealed: true }
      });

      console.log(`✅ IP AUTO-UNBLOCKED: ${ip} (block expired)`);
      return { blocked: false };
    }

    return { blocked: true, until: blocked.blockedUntil, reason: blocked.reason };
  } catch (error) {
    console.error('IP check error:', error.message);
    return { blocked: false };
  }
};

/**
 * RULE 3: Detect SQL injection patterns in request body/query
 */
const detectInjection = (data) => {
  if (!data) return false;
  
  const str = JSON.stringify(data).toLowerCase();
  const sqlPatterns = [
    /(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bunion\b)/i,
    /(--)|(;--|\/\*|\*\/)/,
    /(\bor\b|\band\b)\s+\d+=\d+/i,
    /xp_cmdshell/i,
    /exec\s*\(/i
  ];

  const xssPatterns = [
    /<script[\s\S]*?>/i,
    /javascript:/i,
    /on\w+\s*=/i, // onclick=, onload=, etc.
    /<iframe/i,
    /eval\s*\(/i
  ];

  for (const pattern of [...sqlPatterns, ...xssPatterns]) {
    if (pattern.test(str)) {
      return true;
    }
  }

  return false;
};

/**
 * Get current request stats for dashboard
 */
const getStats = () => {
  const stats = {};
  for (const [ip, data] of requestTracker.entries()) {
    stats[ip] = data;
  }
  return stats;
};

module.exports = {
  trackRequest,
  trackFailedLogin,
  resetFailedLogins,
  autoBlockIP,
  isIPBlocked,
  detectInjection,
  getStats
};
