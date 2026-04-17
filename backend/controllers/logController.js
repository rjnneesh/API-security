// controllers/logController.js
// Handles fetching and managing security logs

const Log = require('../models/Log');
const BlockedIP = require('../models/BlockedIP');

/**
 * @route   GET /api/logs
 * @desc    Get all logs (paginated)
 * @access  Admin only
 */
const getLogs = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    // Filter options
    const filter = {};
    if (req.query.type) filter.type = req.query.type;
    if (req.query.threat === 'true') filter.isThreat = true;
    if (req.query.ip) filter.ip = req.query.ip;
    if (req.query.severity) filter.severity = req.query.severity;

    const logs = await Log.find(filter)
      .sort({ timestamp: -1 }) // Newest first
      .skip(skip)
      .limit(limit)
      .populate('userId', 'username email');

    const total = await Log.countDocuments(filter);

    res.status(200).json({
      success: true,
      count: logs.length,
      total,
      page,
      pages: Math.ceil(total / limit),
      data: logs
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/logs/threats
 * @desc    Get only threat logs
 * @access  Admin only
 */
const getThreatLogs = async (req, res) => {
  try {
    const logs = await Log.find({ isThreat: true })
      .sort({ timestamp: -1 })
      .limit(100);

    res.status(200).json({ success: true, count: logs.length, data: logs });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/logs/stats
 * @desc    Get statistics for dashboard graphs
 * @access  Admin only
 */
const getStats = async (req, res) => {
  try {
    const now = new Date();
    const last24h = new Date(now - 24 * 60 * 60 * 1000);
    const last7d = new Date(now - 7 * 24 * 60 * 60 * 1000);

    // Total requests in last 24h
    const totalRequests24h = await Log.countDocuments({
      timestamp: { $gte: last24h }
    });

    // Threats in last 24h
    const threats24h = await Log.countDocuments({
      timestamp: { $gte: last24h },
      isThreat: true
    });

    // Currently blocked IPs
    const blockedIPs = await BlockedIP.countDocuments({
      isActive: true,
      blockedUntil: { $gt: now }
    });

    // Requests per hour for last 24h (for graph)
    const hourlyStats = await Log.aggregate([
      { $match: { timestamp: { $gte: last24h } } },
      {
        $group: {
          _id: {
            hour: { $hour: '$timestamp' },
            isThreat: '$isThreat'
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.hour': 1 } }
    ]);

    // Top suspicious IPs
    const topThreats = await Log.aggregate([
      { $match: { isThreat: true, timestamp: { $gte: last7d } } },
      { $group: { _id: '$ip', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    // Breakdown by severity
    const severityBreakdown = await Log.aggregate([
      { $match: { timestamp: { $gte: last24h } } },
      { $group: { _id: '$severity', count: { $sum: 1 } } }
    ]);

    // Recent activity (last 10 events)
    const recentActivity = await Log.find()
      .sort({ timestamp: -1 })
      .limit(10)
      .select('type method endpoint ip message isThreat severity timestamp');

    res.status(200).json({
      success: true,
      data: {
        totalRequests24h,
        threats24h,
        blockedIPs,
        safeRequests: totalRequests24h - threats24h,
        threatPercentage: totalRequests24h > 0
          ? ((threats24h / totalRequests24h) * 100).toFixed(1)
          : 0,
        hourlyStats,
        topThreats,
        severityBreakdown,
        recentActivity
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/logs/blocked-ips
 * @desc    Get all blocked IPs
 * @access  Admin only
 */
const getBlockedIPs = async (req, res) => {
  try {
    const blockedIPs = await BlockedIP.find({ isActive: true })
      .sort({ blockedAt: -1 });

    res.status(200).json({ success: true, count: blockedIPs.length, data: blockedIPs });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   DELETE /api/logs/blocked-ips/:ip
 * @desc    Manually unblock an IP (admin action)
 * @access  Admin only
 */
const unblockIP = async (req, res) => {
  try {
    const { ip } = req.params;

    await BlockedIP.findOneAndUpdate({ ip }, { isActive: false });

    await Log.create({
      type: 'heal',
      method: 'DELETE',
      endpoint: `/api/logs/blocked-ips/${ip}`,
      ip: req.ip,
      message: `🔓 MANUAL UNBLOCK: Admin unblocked IP ${ip}`,
      isThreat: false,
      severity: 'low',
      userId: req.user._id,
      details: { unblockedBy: req.user.username }
    });

    res.status(200).json({ success: true, message: `IP ${ip} has been unblocked` });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { getLogs, getThreatLogs, getStats, getBlockedIPs, unblockIP };
