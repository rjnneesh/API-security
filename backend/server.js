// server.js
// Main entry point for API Sentinel backend

require('dotenv').config();

// Allow booting without a .env file by applying sane runtime defaults.
if (!process.env.MONGO_URI) {
  process.env.MONGO_URI = 'mongodb://localhost:27017/api_sentinel';
}

if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = 'api_sentinel_dev_secret_change_me';
}

if (!process.env.JWT_EXPIRE) {
  process.env.JWT_EXPIRE = '7d';
}

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const path = require('path');

const connectDB = require('./config/database');
const { requestLogger, anomalyDetector } = require('./middleware/security');

// Import routes
const authRoutes = require('./routes/auth');
const logRoutes = require('./routes/logs');
const apiRoutes = require('./routes/api');

const FRONTEND_URL = process.env.FRONTEND_URL || 'https://api-security-five.vercel.app';
const BACKEND_URL = process.env.BACKEND_URL || 'https://api-security-5q8p.onrender.com';

const normalizeOrigin = (value) => {
  if (!value) return '';

  try {
    return new URL(value).origin;
  } catch (error) {
    return String(value).trim().replace(/\/$/, '');
  }
};

const allowedOrigins = new Set([
  normalizeOrigin(FRONTEND_URL),
  normalizeOrigin(BACKEND_URL),
  'http://localhost:3000',
  'http://localhost:5000',
  'http://localhost:5001',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5000',
  'http://127.0.0.1:5001'
]);

if (process.env.CORS_ORIGINS) {
  process.env.CORS_ORIGINS
    .split(',')
    .map((origin) => normalizeOrigin(origin))
    .filter(Boolean)
    .forEach((origin) => allowedOrigins.add(origin));
}

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true);
    }

    const normalizedOrigin = normalizeOrigin(origin);
    if (allowedOrigins.has(normalizedOrigin)) {
      return callback(null, true);
    }

    return callback(new Error(`Not allowed by CORS: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// ==========================================
// Initialize Express + HTTP + Socket.io
// ==========================================
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: Array.from(allowedOrigins),
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Connect to MongoDB
connectDB();

// ==========================================
// SECURITY HEADERS (Helmet.js)
// Adds important HTTP security headers
// ==========================================
app.use(helmet({
  contentSecurityPolicy: false, // Disable for now (would break inline scripts)
  crossOriginEmbedderPolicy: false
}));

// ==========================================
// CORS CONFIGURATION
// Controls which origins can call our API
// ==========================================
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ==========================================
// GLOBAL RATE LIMITER
// 100 requests per 15 minutes per IP
// ==========================================
const globalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: {
    success: false,
    message: 'Too many requests from this IP. Please try again later.'
  },
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false
});
app.use('/api/', globalLimiter);

// Stricter limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // Only 20 login/register attempts per 15 mins
  message: { success: false, message: 'Too many auth attempts. Please wait.' }
});
app.use('/api/auth', authLimiter);

// ==========================================
// BODY PARSING
// ==========================================
app.use(express.json({ limit: '10kb' })); // Limit request body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ==========================================
// INPUT SANITIZATION
// Prevents MongoDB injection attacks
// ==========================================
app.use(mongoSanitize());

// ==========================================
// CUSTOM MIDDLEWARE (runs on every request)
// ==========================================
app.use(requestLogger(io));   // Log every request
app.use(anomalyDetector(io)); // Detect anomalies

// ==========================================
// STATIC FILES (Frontend)
// Serves HTML/CSS/JS from frontend folder
// ==========================================
app.use(express.static(path.join(__dirname, '../frontend')));

// ==========================================
// API ROUTES
// ==========================================
app.use('/api/auth', authRoutes);
app.use('/api/logs', logRoutes);
app.use('/api/test', apiRoutes);

// Root route → serve dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

// ==========================================
// SOCKET.IO - Real-time events
// ==========================================
io.on('connection', (socket) => {
  console.log(`🔌 Dashboard connected: ${socket.id}`);
  
  socket.emit('connected', { message: 'Connected to API Sentinel real-time feed' });

  socket.on('disconnect', () => {
    console.log(`🔌 Dashboard disconnected: ${socket.id}`);
  });
});

// Make io accessible in other files
app.set('io', io);

// ==========================================
// 404 HANDLER
// ==========================================
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`
  });
});

// ==========================================
// GLOBAL ERROR HANDLER
// ==========================================
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error'
  });
});

// ==========================================
// START SERVER
// ==========================================
const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════════╗
  ║         🛡️  API SENTINEL v1.0.0          ║
  ║  Security Monitoring & Self-Healing API  ║
  ╠══════════════════════════════════════════╣
  ║  Server  : http://localhost:${PORT}         ║
  ║  Mode    : ${process.env.NODE_ENV || 'development'}                  ║
  ║  Dashboard: http://localhost:${PORT}        ║
  ╚══════════════════════════════════════════╝
  `);
});

module.exports = { app, io };
