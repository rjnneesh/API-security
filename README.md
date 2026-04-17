# 🛡️ API Sentinel — Enterprise API Security Solution

> A complete full-stack cybersecurity project featuring anomaly detection, real-time monitoring, self-healing mechanisms, and a live security dashboard.

---

## 📁 Project Structure

```
api-sentinel/
├── backend/
│   ├── config/
│   │   └── database.js          # MongoDB connection
│   ├── controllers/
│   │   ├── authController.js    # Register / Login logic
│   │   └── logController.js     # Logs & stats API
│   ├── middleware/
│   │   └── security.js          # JWT auth, anomaly detector, request logger
│   ├── models/
│   │   ├── User.js              # User schema (bcrypt hashed passwords)
│   │   ├── Log.js               # All request + event logs
│   │   └── BlockedIP.js         # Auto-blocked IP records
│   ├── routes/
│   │   ├── auth.js              # /api/auth/*
│   │   ├── logs.js              # /api/logs/*  (admin only)
│   │   └── api.js               # /api/test/*  (demo endpoints)
│   ├── utils/
│   │   └── anomalyDetector.js   # Core rule-based detection engine
│   ├── server.js                # Main Express + Socket.io server
│   ├── package.json
│   └── .env                     # Environment variables
│
├── frontend/
│   ├── css/
│   │   └── style.css            # Full UI styling (dark cyberpunk theme)
│   ├── js/
│   │   └── dashboard.js         # Dashboard logic, charts, real-time
│   ├── pages/
│   │   ├── dashboard.html       # Main admin dashboard
│   │   └── register.html        # Registration page
│   └── index.html               # Login page
│
├── API-Sentinel-Postman.json    # Postman test collection
└── README.md                    # This file
```

---

## ⚙️ Prerequisites

Make sure you have these installed:

| Tool | Version | Download |
|------|---------|----------|
| Node.js | v16+ | https://nodejs.org |
| MongoDB | v6+ | https://www.mongodb.com/try/download/community |
| npm | v8+ | Comes with Node.js |

---

## 🚀 Setup Guide (Step by Step)

### Step 1 — Clone / Extract Project

```bash
# If using git
git clone <your-repo-url>
cd api-sentinel

# Or just extract the ZIP and navigate to it
cd api-sentinel
```

### Step 2 — Install Backend Dependencies

```bash
cd backend
npm install
```

This installs: Express, Mongoose, JWT, Bcrypt, Helmet, Socket.io, etc.

### Step 3 — Start MongoDB

```bash
# On Windows (if MongoDB is installed as a service, it may already be running)
net start MongoDB

# On Mac
brew services start mongodb-community

# On Linux
sudo systemctl start mongod

# Or run directly
mongod --dbpath /data/db
```

Verify MongoDB is running:
```bash
mongosh
# You should see a MongoDB prompt
```

### Step 4 — Configure Environment Variables

The `.env` file is already created. Review and update if needed:

```env
PORT=5000
MONGO_URI=mongodb://localhost:27017/api_sentinel
JWT_SECRET=your_super_secret_key_change_this
JWT_EXPIRE=7d

# Anomaly thresholds
REQUESTS_PER_MINUTE_THRESHOLD=30
FAILED_LOGIN_THRESHOLD=5
BLOCK_DURATION_MINUTES=30
```

### Step 5 — Run the Server

```bash
# From the backend/ directory:

# Production mode
node server.js

# Development mode (auto-restarts on file changes)
npm run dev
```

You should see:
```
╔══════════════════════════════════════════╗
║         🛡️  API SENTINEL v1.0.0          ║
╠══════════════════════════════════════════╣
║  Server  : http://localhost:5000         ║
╚══════════════════════════════════════════╝
✅ MongoDB Connected: localhost
```

### Step 6 — Open the Dashboard

Open your browser and go to:
```
http://localhost:5000
```

You'll see the login page. Register an admin account first, then login.

---

## 🔑 First-Time Setup

1. Go to `http://localhost:5000/pages/register.html`
2. Create an **Admin** account (select "Admin" role)
3. Login at `http://localhost:5000`
4. You now have full access to the dashboard

---

## 📡 API Endpoints Reference

### Authentication
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | No | Register new user |
| POST | `/api/auth/login` | No | Login & get JWT token |
| GET | `/api/auth/me` | JWT | Get current user profile |

### Logs & Monitoring (Admin Only)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/logs` | All logs (paginated, filterable) |
| GET | `/api/logs/threats` | Threat-only logs |
| GET | `/api/logs/stats` | Dashboard statistics |
| GET | `/api/logs/blocked-ips` | Active blocked IPs |
| DELETE | `/api/logs/blocked-ips/:ip` | Manually unblock an IP |

### Test Endpoints
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/test/public` | No | Public endpoint (unprotected) |
| GET | `/api/test/protected` | JWT | Protected endpoint |
| POST | `/api/test/data-integrity` | JWT | SHA-256 hash demonstration |
| GET | `/api/test/health` | No | Server health check |

---

## 🧪 Testing with Postman

### Import the Collection
1. Open Postman
2. Click **Import** → upload `API-Sentinel-Postman.json`
3. The full test collection loads automatically

### Test Order
1. **Register Admin** — Creates your admin account
2. **Login** — Gets JWT token (auto-saved to collection variable)
3. **Get Profile** — Verify token works
4. **SQL Injection Test** — Should return 400 BLOCKED
5. **XSS Attack Test** — Should return 400 BLOCKED
6. **Wrong Password × 5** — Should trigger IP block
7. **View Logs** — See all events in database
8. **View Blocked IPs** — See auto-blocked IPs

---

## 🔐 Security Features Explained

### 1. JWT Authentication
- Tokens expire in 7 days
- Role-based access (admin vs user)
- All sensitive routes require `Authorization: Bearer <token>` header

### 2. Anomaly Detection (Rule-Based)

**Rule 1 — Rate Limiting:**
```
If requests from IP > 30 per minute → Auto-block IP for 30 minutes
```

**Rule 2 — Failed Login Tracking:**
```
If failed logins from IP >= 5 → Auto-block IP
If user account fails login 5x → Lock user account for 30 minutes
```

**Rule 3 — Injection Detection:**
```
If request body contains SQL patterns (SELECT, DROP, UNION, --, etc.)
OR XSS patterns (<script>, javascript:, onerror=, etc.)
→ Block request + Auto-block IP
```

### 3. Self-Healing Mechanism
- Blocked IPs are automatically unblocked when the block duration expires
- Admin can manually unblock from the dashboard
- All healing events are logged with type `heal`

### 4. Data Integrity
- Passwords hashed with bcrypt (12 salt rounds)
- SHA-256 hashing for sensitive data verification
- HMAC signatures to detect tampering

### 5. Other Security Layers
- **Helmet.js** — Sets 11 security HTTP headers
- **express-mongo-sanitize** — Prevents MongoDB operator injection
- **express-rate-limit** — Global + per-route rate limiting
- **CORS** — Configured to specific allowed origins
- **Body size limit** — 10KB max request body

---

## 📊 Dashboard Features

| Feature | Description |
|---------|-------------|
| Overview | Live stats, traffic charts, threat feed |
| Request Logs | All API calls with method, IP, status, timing |
| Threats | Filtered view of only malicious activity |
| Blocked IPs | Self-healed/blocked IP management |
| API Tester | Test endpoints directly from the UI |
| Real-time Feed | Socket.io live event stream |

---

## 🧰 Tech Stack Summary

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3 (Custom), Vanilla JS, Chart.js |
| Backend | Node.js, Express.js |
| Database | MongoDB with Mongoose ODM |
| Auth | JWT (jsonwebtoken) |
| Security | Helmet, bcryptjs, express-rate-limit, express-mongo-sanitize |
| Real-time | Socket.io |
| Fonts | Orbitron, Share Tech Mono, Rajdhani (Google Fonts) |

---

## 💡 How It Works — Architecture Diagram

```
Browser (Dashboard)
        ↕ HTTP + WebSocket (Socket.io)
Express Server (server.js)
        ↓
  [Middleware Stack — runs on EVERY request]
  1. Helmet (security headers)
  2. CORS check
  3. Global Rate Limiter
  4. Body parser + size limit
  5. MongoDB sanitizer
  6. requestLogger → logs to DB + emits to Socket.io
  7. anomalyDetector → checks IP block, rate, injection
        ↓
  [Routes]
  /api/auth → Register / Login / Profile
  /api/logs → Stats / Logs / Blocked IPs (admin only)
  /api/test → Demo endpoints
        ↓
  MongoDB (api_sentinel database)
  - users collection
  - logs collection
  - blockedips collection
```

---

## 🎓 College Demo Script

**Step 1:** Show the dashboard running at localhost:5000

**Step 2:** Open Postman → Send 35+ rapid requests to `/api/test/public`
→ Watch the IP get auto-blocked in real-time on dashboard

**Step 3:** Try logging in with wrong password 5 times
→ Show account lockout message and log entry

**Step 4:** Send SQL injection payload
→ Show it gets intercepted and blocked

**Step 5:** Go to Blocked IPs tab
→ Show the auto-blocked entries with reasons

**Step 6:** Manually unblock an IP (admin action)
→ Show self-healing log entry created

**Step 7:** Show security headers using browser DevTools → Network tab
→ Point out X-Frame-Options, X-Content-Type-Options, etc.

---

## 🐛 Troubleshooting

**"Cannot connect to MongoDB"**
→ Make sure MongoDB is running: `mongod` or `sudo systemctl start mongod`

**"Port 5000 already in use"**
→ Change `PORT=5001` in `.env`

**"Module not found"**
→ Run `npm install` inside the `backend/` folder

**Dashboard shows no data**
→ Make sure you registered an admin account and are logged in

**Socket.io not connecting**
→ Check browser console. The dashboard works without it (polling fallback)
