// frontend/js/dashboard.js
// All dashboard logic: auth check, data fetching, charts, real-time feed

// =============================================
// AUTH GUARD - Redirect if not logged in
// =============================================
const API_URL = "https://api-security-5q8p.onrender.com";
const token = localStorage.getItem('token');
const user = JSON.parse(localStorage.getItem('user') || '{}');

if (!token || !user.id) {
  window.location.href = '/';
}

// Set user info in sidebar
document.getElementById('userName').textContent = user.username || 'Unknown';
document.getElementById('userRole').textContent = user.role ? user.role.toUpperCase() : 'USER';
document.getElementById('userAvatar').textContent = (user.username || 'U')[0].toUpperCase();

// Update clock
function updateClock() {
  const el = document.getElementById('currentTime');
  if (el) el.textContent = new Date().toLocaleString();
}
updateClock();
setInterval(updateClock, 1000);

// =============================================
// API HELPER
// =============================================
async function apiCall(url, method = 'GET', body = null) {
  const options = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  };
  if (body) options.body = JSON.stringify(body);

  const res = await fetch(url, options);
  const data = await res.json();

  // If token expired, redirect to login
  if (res.status === 401) {
    localStorage.clear();
    window.location.href = '/';
  }

  return { status: res.status, data };
}

// =============================================
// NAVIGATION - Show/hide sections
// =============================================
function showSection(name) {
  // Hide all sections
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  // Remove active from all nav items
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  // Show selected section
  document.getElementById('section-' + name).classList.add('active');

  // Mark nav item active
  event.currentTarget.classList.add('active');

  // Load data for the section
  if (name === 'overview') loadOverview();
  if (name === 'logs') loadLogs();
  if (name === 'threats') loadThreats();
  if (name === 'blocked') loadBlockedIPs();
}

function logout() {
  localStorage.clear();
  window.location.href = '/';
}

// =============================================
// SOCKET.IO - Real-time connection
// =============================================
let socket;
try {
  socket = io(window.location.origin);

  socket.on('connect_error', (err) => {
    console.error('Socket connect error:', err);
  });

  socket.on('connect', () => {
    document.getElementById('connDot').style.background = 'var(--accent-green)';
    document.getElementById('connDot').style.boxShadow = '0 0 6px var(--accent-green)';
    document.getElementById('connText').textContent = 'LIVE';
  });

  socket.on('disconnect', () => {
    document.getElementById('connDot').style.background = 'var(--accent-red)';
    document.getElementById('connDot').style.boxShadow = '0 0 6px var(--accent-red)';
    document.getElementById('connText').textContent = 'DISCONNECTED';
  });

  // New log event - add to live feed
  socket.on('new-log', (log) => {
    addToLiveFeed(log);
  });

  // Security alert - show warning
  socket.on('security-alert', (alert) => {
    addToLiveFeed({
      isThreat: true,
      message: `🚨 ALERT: ${alert.reason} — IP: ${alert.ip}`,
      timestamp: alert.timestamp
    });

    // Flash status badge red
    const statusBadge = document.getElementById('systemStatus');
    const statusText = document.getElementById('statusText');
    statusBadge.classList.add('threat');
    statusText.textContent = 'THREAT DETECTED';

    // Reset after 5 seconds
    setTimeout(() => {
      statusBadge.classList.remove('threat');
      statusText.textContent = 'SYSTEM SECURE';
    }, 5001);
  });
} catch (e) {
  console.warn('Socket.io not available:', e.message);
}

// =============================================
// LIVE FEED
// =============================================
const MAX_FEED_ITEMS = 50;

function addToLiveFeed(log) {
  const feed = document.getElementById('alertsFeed');
  
  // Remove placeholder if present
  const placeholder = feed.querySelector('[data-placeholder]');
  if (placeholder) placeholder.remove();

  const item = document.createElement('div');
  item.className = 'alert-item';

  const dotClass = log.isThreat ? 'threat' : 'safe';
  const time = new Date(log.timestamp).toLocaleTimeString();
  const msg = log.message || `${log.method} ${log.endpoint}`;

  item.innerHTML = `
    <div class="alert-dot ${dotClass}"></div>
    <div class="alert-msg">${escapeHtml(msg.substring(0, 80))}</div>
    <div class="alert-time">${time}</div>
  `;

  // Add to top of feed
  feed.insertBefore(item, feed.firstChild);

  // Keep feed from getting too long
  while (feed.children.length > MAX_FEED_ITEMS) {
    feed.removeChild(feed.lastChild);
  }
}

// =============================================
// OVERVIEW - Stats + Charts
// =============================================
let trafficChart = null;
let severityChart = null;

async function loadOverview() {
  try {
    const { data } = await apiCall('/api/logs/stats');
    if (!data.success) return;

    const stats = data.data;

    // Update stat cards
    document.getElementById('statTotal').textContent = stats.totalRequests24h || 0;
    document.getElementById('statThreats').textContent = stats.threats24h || 0;
    document.getElementById('statSafe').textContent = stats.safeRequests || 0;
    document.getElementById('statBlocked').textContent = stats.blockedIPs || 0;

    // Build traffic chart
    buildTrafficChart(stats.hourlyStats || []);

    // Build severity chart
    buildSeverityChart(stats.severityBreakdown || []);

    // Populate top threats
    populateTopThreats(stats.topThreats || []);

    // Populate live feed with recent activity
    const feed = document.getElementById('alertsFeed');
    feed.innerHTML = '';
    (stats.recentActivity || []).forEach(log => addToLiveFeed(log));

    if (!stats.recentActivity || stats.recentActivity.length === 0) {
      feed.innerHTML = '<div data-placeholder style="padding:1rem;text-align:center;color:var(--text-muted);font-family:var(--font-mono);font-size:0.8rem;">No recent activity</div>';
    }
  } catch (err) {
    console.error('Overview load error:', err);
  }
}

function buildTrafficChart(hourlyStats) {
  const ctx = document.getElementById('trafficChart');
  if (!ctx) return;

  // Build hour labels 0-23
  const labels = Array.from({length: 24}, (_, i) => `${i}:00`);
  const normalData = new Array(24).fill(0);
  const threatData = new Array(24).fill(0);

  hourlyStats.forEach(item => {
    const hour = item._id.hour;
    if (item._id.isThreat) {
      threatData[hour] = item.count;
    } else {
      normalData[hour] = item.count;
    }
  });

  if (trafficChart) trafficChart.destroy();

  trafficChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Normal',
          data: normalData,
          backgroundColor: 'rgba(16, 185, 129, 0.4)',
          borderColor: 'rgba(16, 185, 129, 0.8)',
          borderWidth: 1
        },
        {
          label: 'Threats',
          data: threatData,
          backgroundColor: 'rgba(239, 68, 68, 0.4)',
          borderColor: 'rgba(239, 68, 68, 0.8)',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#94a3b8', font: { family: 'Share Tech Mono', size: 10 } } }
      },
      scales: {
        x: { ticks: { color: '#475569', font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#475569' }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    }
  });
}

function buildSeverityChart(severityData) {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;

  const labels = ['Low', 'Medium', 'High', 'Critical'];
  const colors = ['rgba(16,185,129,0.7)', 'rgba(245,158,11,0.7)', 'rgba(239,68,68,0.7)', 'rgba(139,92,246,0.7)'];
  const counts = labels.map(l => {
    const found = severityData.find(s => s._id === l.toLowerCase());
    return found ? found.count : 0;
  });

  if (severityChart) severityChart.destroy();

  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: counts,
        backgroundColor: colors,
        borderColor: 'rgba(0,0,0,0.3)',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#94a3b8', font: { family: 'Share Tech Mono', size: 10 }, padding: 10 }
        }
      }
    }
  });
}

function populateTopThreats(threats) {
  const container = document.getElementById('topThreats');
  if (!threats || threats.length === 0) {
    container.innerHTML = '<div style="text-align:center;color:var(--text-muted);font-family:var(--font-mono);font-size:0.8rem;">No threat data yet</div>';
    return;
  }

  const maxCount = threats[0]?.count || 1;

  container.innerHTML = threats.map((t, i) => `
    <div style="margin-bottom:0.75rem;">
      <div style="display:flex;justify-content:space-between;margin-bottom:0.25rem;">
        <span style="font-family:var(--font-mono);font-size:0.8rem;color:var(--accent-red);">${escapeHtml(t._id)}</span>
        <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);">${t.count} hits</span>
      </div>
      <div style="background:var(--bg-secondary);border-radius:3px;height:6px;overflow:hidden;">
        <div style="background:var(--accent-red);height:100%;width:${(t.count/maxCount*100).toFixed(0)}%;transition:width 0.5s;opacity:0.7;"></div>
      </div>
    </div>
  `).join('');
}

// =============================================
// LOGS TABLE
// =============================================
let currentPage = 1;
let totalPages = 1;

async function loadLogs() {
  const type = document.getElementById('logTypeFilter')?.value || '';
  const threat = document.getElementById('logThreatFilter')?.value || '';
  const severity = document.getElementById('logSeverityFilter')?.value || '';

  let url = `/api/logs?page=${currentPage}&limit=20`;
  if (type) url += `&type=${type}`;
  if (threat) url += `&threat=${threat}`;
  if (severity) url += `&severity=${severity}`;

  const tbody = document.getElementById('logsTableBody');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--text-muted);">Loading...</td></tr>';

  try {
    const { data } = await apiCall(url);
    if (!data.success) return;

    totalPages = data.pages || 1;
    document.getElementById('logCount').textContent = `${data.total} total logs`;
    document.getElementById('pageInfo').textContent = `${currentPage} / ${totalPages}`;

    if (data.data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--text-muted);">No logs found</td></tr>';
      return;
    }

    tbody.innerHTML = data.data.map(log => `
      <tr>
        <td>${new Date(log.timestamp).toLocaleTimeString()}</td>
        <td class="method-${(log.method || 'get').toLowerCase()}">${log.method || '-'}</td>
        <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(log.endpoint)}">${escapeHtml(log.endpoint)}</td>
        <td>${escapeHtml(log.ip)}</td>
        <td>${getStatusBadge(log.statusCode)}</td>
        <td>${getSeverityBadge(log.severity)}</td>
        <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(log.message)}">${escapeHtml(log.message)}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--accent-red);">Error loading logs</td></tr>';
  }
}

function changePage(dir) {
  const newPage = currentPage + dir;
  if (newPage < 1 || newPage > totalPages) return;
  currentPage = newPage;
  loadLogs();
}

// =============================================
// THREATS TABLE
// =============================================
async function loadThreats() {
  const tbody = document.getElementById('threatsTableBody');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--text-muted);">Loading...</td></tr>';

  try {
    const { data } = await apiCall('/api/logs/threats');
    if (!data.success) return;

    if (data.data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--accent-green);">✅ No threats detected</td></tr>';
      return;
    }

    tbody.innerHTML = data.data.map(log => `
      <tr>
        <td>${new Date(log.timestamp).toLocaleString()}</td>
        <td>${getThreatTypeBadge(log.type)}</td>
        <td style="color:var(--accent-red);">${escapeHtml(log.ip)}</td>
        <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(log.endpoint)}</td>
        <td>${getSeverityBadge(log.severity)}</td>
        <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(log.message)}">${escapeHtml(log.message)}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--accent-red);">Error loading threats</td></tr>';
  }
}

// =============================================
// BLOCKED IPs
// =============================================
async function loadBlockedIPs() {
  const container = document.getElementById('blockedIPList');
  const countBadge = document.getElementById('blockedCount');
  container.innerHTML = '<div style="text-align:center;color:var(--text-muted);font-family:var(--font-mono);font-size:0.8rem;">Loading...</div>';

  try {
    const { data } = await apiCall('/api/logs/blocked-ips');
    if (!data.success) return;

    countBadge.textContent = `${data.count} IPs`;

    if (data.data.length === 0) {
      container.innerHTML = '<div style="text-align:center;color:var(--accent-green);font-family:var(--font-mono);font-size:0.85rem;padding:1rem;">✅ No IPs are currently blocked</div>';
      return;
    }

    container.innerHTML = data.data.map(ip => `
      <div class="ip-card">
        <div>
          <div class="ip-address">🚫 ${escapeHtml(ip.ip)}</div>
          <div class="ip-reason">${escapeHtml(ip.reason)}</div>
          <div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);margin-top:0.25rem;">
            Flagged ${ip.flagCount}x • Expires: ${new Date(ip.blockedUntil).toLocaleString()}
          </div>
        </div>
        ${user.role === 'admin' ? `
          <button class="btn btn-danger" onclick="unblockIP('${escapeHtml(ip.ip)}')">
            🔓 UNBLOCK
          </button>
        ` : ''}
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = '<div style="text-align:center;color:var(--accent-red);">Error loading blocked IPs</div>';
  }
}

async function unblockIP(ip) {
  if (!confirm(`Unblock IP: ${ip}?`)) return;

  try {
    const { data } = await apiCall(`/api/logs/blocked-ips/${encodeURIComponent(ip)}`, 'DELETE');
    if (data.success) {
      alert(`✅ ${data.message}`);
      loadBlockedIPs();
    } else {
      alert('Failed: ' + data.message);
    }
  } catch (err) {
    alert('Error unblocking IP');
  }
}

// =============================================
// API TESTER
// =============================================
async function testEndpoint(method, url) {
  const responseEl = document.getElementById('testResponse');
  const statusEl = document.getElementById('testStatus');

  responseEl.textContent = 'Loading...';
  statusEl.textContent = 'SENDING';
  statusEl.className = 'badge badge-info';

  try {
    const { status, data } = await apiCall(url, method);
    responseEl.textContent = JSON.stringify(data, null, 2);
    statusEl.textContent = `${status} OK`;
    statusEl.className = status < 400 ? 'badge badge-safe' : 'badge badge-threat';
  } catch (err) {
    responseEl.textContent = 'Error: ' + err.message;
    statusEl.textContent = 'ERROR';
    statusEl.className = 'badge badge-threat';
  }
}

async function testDataIntegrity() {
  const responseEl = document.getElementById('testResponse');
  const statusEl = document.getElementById('testStatus');

  responseEl.textContent = 'Loading...';

  try {
    const { status, data } = await apiCall('/api/test/data-integrity', 'POST', {
      data: { userId: 123, action: 'transfer', amount: 5001 }
    });
    responseEl.textContent = JSON.stringify(data, null, 2);
    statusEl.textContent = `${status}`;
    statusEl.className = status < 400 ? 'badge badge-safe' : 'badge badge-threat';
  } catch (err) {
    responseEl.textContent = 'Error: ' + err.message;
  }
}

async function testInjection() {
  const responseEl = document.getElementById('testResponse');
  const statusEl = document.getElementById('testStatus');

  responseEl.textContent = 'Sending injection payload...';

  try {
    // Send a known SQL injection pattern - should be blocked
    const res = await fetch('https://api-security-5q8p.onrender.com/api/test/public', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ query: "SELECT * FROM users; DROP TABLE users;--" })
    });
    const data = await res.json();
    responseEl.textContent = JSON.stringify(data, null, 2);
    statusEl.textContent = res.status === 400 ? 'BLOCKED ✓' : `${res.status}`;
    statusEl.className = res.status === 400 ? 'badge badge-safe' : 'badge badge-threat';
  } catch (err) {
    responseEl.textContent = 'Error: ' + err.message;
  }
}

// =============================================
// BADGE HELPERS
// =============================================
function getStatusBadge(code) {
  if (!code) return '<span class="badge badge-info">--</span>';
  if (code < 300) return `<span class="badge badge-safe">${code}</span>`;
  if (code < 400) return `<span class="badge badge-info">${code}</span>`;
  if (code < 500) return `<span class="badge badge-threat">${code}</span>`;
  return `<span class="badge badge-critical">${code}</span>`;
}

function getSeverityBadge(sev) {
  const map = {
    low: 'safe', medium: 'warn', high: 'threat', critical: 'critical'
  };
  return `<span class="badge badge-${map[sev] || 'info'}">${sev || 'low'}</span>`;
}

function getThreatTypeBadge(type) {
  const map = {
    anomaly: 'badge-threat',
    block: 'badge-critical',
    auth: 'badge-warn',
    heal: 'badge-safe',
    request: 'badge-info'
  };
  return `<span class="badge ${map[type] || 'badge-info'}">${type}</span>`;
}

// =============================================
// SECURITY HELPER
// =============================================
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// =============================================
// INITIAL LOAD
// =============================================
loadOverview();

// Auto-refresh overview every 30 seconds
setInterval(() => {
  const overviewSection = document.getElementById('section-overview');
  if (overviewSection && overviewSection.classList.contains('active')) {
    loadOverview();
  }
}, 30000);
