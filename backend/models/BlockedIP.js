// models/BlockedIP.js
// Tracks blocked IP addresses for self-healing

const mongoose = require('mongoose');

const BlockedIPSchema = new mongoose.Schema({
  ip: {
    type: String,
    required: true,
    unique: true
  },

  // Why was this IP blocked?
  reason: {
    type: String,
    required: true
  },

  // How many times has this IP been flagged?
  flagCount: {
    type: Number,
    default: 1
  },

  // When does the block expire? (null = permanent)
  blockedUntil: {
    type: Date,
    required: true
  },

  isActive: {
    type: Boolean,
    default: true
  },

  blockedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('BlockedIP', BlockedIPSchema);
