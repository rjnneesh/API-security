// models/Log.js
// Stores all API request logs and security events

const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
  // What type of log is this?
  type: {
    type: String,
    enum: ['request', 'anomaly', 'block', 'auth', 'heal', 'info'],
    default: 'request'
  },

  // HTTP method (GET, POST, etc.)
  method: {
    type: String,
    default: 'UNKNOWN'
  },

  // Which endpoint was hit
  endpoint: {
    type: String,
    required: true
  },

  // Client IP address
  ip: {
    type: String,
    required: true
  },

  // HTTP response status code
  statusCode: {
    type: Number,
    default: 200
  },

  // How long the request took
  responseTime: {
    type: Number, // in milliseconds
    default: 0
  },

  // User agent string (browser/client info)
  userAgent: {
    type: String,
    default: 'Unknown'
  },

  // Logged-in user (if any)
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },

  // Human-readable description of what happened
  message: {
    type: String,
    required: true
  },

  // Is this a security threat?
  isThreat: {
    type: Boolean,
    default: false
  },

  // Severity level
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },

  // Extra data about the event
  details: {
    type: Object,
    default: {}
  },

  timestamp: {
    type: Date,
    default: Date.now
  }
});

// Index for fast queries on common fields
LogSchema.index({ timestamp: -1 });
LogSchema.index({ ip: 1 });
LogSchema.index({ isThreat: 1 });
LogSchema.index({ type: 1 });

module.exports = mongoose.model('Log', LogSchema);
