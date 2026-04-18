// server.js
// Main entry point for API Sentinel backend

require('dotenv').config();
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

// ==========================================
// Initialize Express + HTTP + Socket.io
// ==========================================
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*', // In production, restrict to your frontend domain
    methods: ['GET', 'POST']
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
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5001', 'http://127.0.0.1:5001','https://api-security-5q8p.onrender.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

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
