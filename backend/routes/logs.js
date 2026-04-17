// routes/logs.js
const express = require('express');
const router = express.Router();
const { getLogs, getThreatLogs, getStats, getBlockedIPs, unblockIP } = require('../controllers/logController');
const { protect, authorize } = require('../middleware/security');

// All routes below require authentication + admin role
router.use(protect);
router.use(authorize('admin'));

router.get('/', getLogs);
router.get('/threats', getThreatLogs);
router.get('/stats', getStats);
router.get('/blocked-ips', getBlockedIPs);
router.delete('/blocked-ips/:ip', unblockIP);

module.exports = router;
