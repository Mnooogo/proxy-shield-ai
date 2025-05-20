require('dotenv').config();
const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'verysecretjwtkey';
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

app.use(cors());
app.use(express.json());

const blockedPath = path.join(__dirname, 'blocked.json');
let blockedIPs = fs.existsSync(blockedPath) ? JSON.parse(fs.readFileSync(blockedPath, 'utf8')) : {};
function saveBlocked() {
  fs.writeFileSync(blockedPath, JSON.stringify(blockedIPs, null, 2));
}

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: '⚠️ Too many requests from this IP, please try again later.',
});
app.use(limiter);

const allowedIPs = ['127.0.0.1', '::1'];
const logPath = path.join(__dirname, 'proxy_log.txt');
function logActivity(entry) {
  const logEntry = `[${new Date().toISOString()}] ${entry}\n`;
  fs.appendFileSync(logPath, logEntry);
}

const usagePath = path.join(__dirname, 'usage.json');
let usageData = fs.existsSync(usagePath) ? JSON.parse(fs.readFileSync(usagePath, 'utf8')) : {};
function saveUsage() {
  fs.writeFileSync(usagePath, JSON.stringify(usageData, null, 2));
}

const userUsagePath = path.join(__dirname, 'usage_per_user.json');
let usagePerUser = fs.existsSync(userUsagePath) ? JSON.parse(fs.readFileSync(userUsagePath, 'utf8')) : {};
function saveUserUsage() {
  fs.writeFileSync(userUsagePath, JSON.stringify(usagePerUser, null, 2));
}

const requestCountPath = path.join(__dirname, 'requests.json');
let requestsPerDay = fs.existsSync(requestCountPath) ? JSON.parse(fs.readFileSync(requestCountPath, 'utf8')) : {};
function saveRequestCount() {
  fs.writeFileSync(requestCountPath, JSON.stringify(requestsPerDay, null, 2));
}

const ipTimestamps = {};
async function sendTelegramAlert(msg) {
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT_ID) return;
  const url = `https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`;
  try {
    await axios.post(url, {
      chat_id: TELEGRAM_CHAT_ID,
      text: `🚨 Proxy Alert:\n${msg}`,
    });
  } catch (err) {
    console.error('❌ Telegram alert failed:', err.message);
  }
}

const users = [];
const userLimits = { admin: 5000, tester: 1000 }; // Add custom limits per user here
const setupUser = () => {
  const username = process.env.ADMIN_USER || 'admin';
  const rawPass = process.env.ADMIN_PASS || 'password';
  const hash = bcrypt.hashSync(rawPass, 10);
  users.push({ username, passwordHash: hash });
};
setupUser();

function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(403).json({ error: 'Missing or invalid token' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    logActivity(`❌ Failed login attempt: ${username}`);
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '2h' });
  logActivity(`✅ Login success: ${username}`);
  res.send(`
    <html>
      <head>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <head>
        <title>Usage Stats</title>
        <style>
          body { font-family: sans-serif; background: #111; color: #fff; padding: 20px; }
          table { width: 100%; border-collapse: collapse; margin-top: 20px; }
          th, td { padding: 10px; border: 1px solid #555; text-align: left; }
          progress { width: 100%; height: 16px; }
          .reset-btn { margin-top: 20px; padding: 10px 20px; background: crimson; color: white; border: none; cursor: pointer; }
        </style>
      </head>
      <body>
        <h1>📊 Token Usage</h1>
        <p>Total Used: ${totalUsed}</p>
        <p>Free Credits Left: ${creditLeft}</p>
        <p>Remaining Paid Quota: ${remaining}</p>
        <table>
          <thead><tr><th>User</th><th>Tokens Used</th><th>Progress</th></tr></thead>
          <tbody>${usageTableHTML}</tbody>
        </table>
        <form method="POST" action="/admin/reset-usage">
          <button type="submit" class="reset-btn">🔁 Reset All Usage</button>
        </form>
      <canvas id="dailyChart" width="800" height="300"></canvas>
<script>
  const ctx = document.getElementById('dailyChart').getContext('2d');
  fetch('/usage-data')
    .then(res => res.json())
    .then(data => {
      const labels = data.map(row => row.date);
      const values = data.map(row => row.tokens);
      new Chart(ctx, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Tokens Used Per Day',
            data: values,
            backgroundColor: 'goldenrod'
          }]
        },
        options: {
          plugins: {
            legend: { display: false }
          },
          scales: {
            y: { beginAtZero: true }
          }
        }
      });
    });
</script>
</body>
    </html>
  `);
});

app.post('/proxy', authenticateJWT, async (req, res) => {
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || 'unknown';
  const now = Date.now();

  if (blockedIPs[ip] && blockedIPs[ip] > now) {
    logActivity(`⛔ BLOCKED: ${ip} tried to access during ban`);
    return res.status(403).json({ error: 'Your IP is temporarily blocked.' });
  } else if (blockedIPs[ip] && blockedIPs[ip] <= now) {
    delete blockedIPs[ip];
    saveBlocked();
  }

  if (!allowedIPs.includes(ip)) {
    logActivity(`Blocked request from IP: ${ip} | UA: ${userAgent}`);
    return res.status(403).json({ error: 'Access denied.' });
  }

  const { apiKey, messages, model } = req.body;
  if (!apiKey || !messages || !model) {
    logActivity(`Invalid request structure from ${ip}`);
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  requestsPerDay[ip] = (requestsPerDay[ip] || 0) + 1;
  saveRequestCount();

  if (requestsPerDay[ip] > 100) {
    blockedIPs[ip] = now + 24 * 60 * 60 * 1000;
    saveBlocked();
    logActivity(`⛔ IP ${ip} blocked for exceeding daily request limit`);
    return res.status(429).json({ error: 'You have been temporarily blocked for 24 hours due to excessive requests.' });
  }

  ipTimestamps[ip] = ipTimestamps[ip] || [];
  ipTimestamps[ip].push(now);
  ipTimestamps[ip] = ipTimestamps[ip].filter(ts => now - ts < 10000);

  if (ipTimestamps[ip].length > 5) {
    const alertMsg = `🚨 Suspicious activity from ${ip} — ${ipTimestamps[ip].length} requests in 10s`;
    logActivity(alertMsg);
    sendTelegramAlert(alertMsg);
  }

  try {
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      { model, messages },
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
      }
    );

    const tokenUsed = response.data?.usage?.total_tokens || 0;
    usageData[ip] = (usageData[ip] || 0) + tokenUsed;

    if (usageData[ip] > 5000) {
      blockedIPs[ip] = now + 24 * 60 * 60 * 1000;
      saveBlocked();
      logActivity(`⛔ IP ${ip} blocked for exceeding token limit`);
      return res.status(429).json({ error: 'You have been temporarily blocked for 24 hours due to excessive token usage.' });
    }

    saveUsage();
    logActivity(`✅ ${ip} | Tokens: ${tokenUsed} | Total: ${usageData[ip]}`);
    res.json(response.data);
  } catch (error) {
    logActivity(`Error for ${ip} | ${error.message}`);
    res.status(500).json({ error: 'Proxy error', details: error.message });
  }
});

app.get('/usage', authenticateJWT, (req, res) => {
  const usageTableHTML = Object.entries(usagePerUser).map(([user, tokens]) => `
    <tr><td>${user}</td><td>${tokens}</td><td><progress value="${tokens}" max="${userLimits[user] || 10000}"></progress></td></tr>
  `).join('');

  const usageByDayPath = path.join(__dirname, 'usage_by_day.json');
  let usageByDay = fs.existsSync(usageByDayPath) ? JSON.parse(fs.readFileSync(usageByDayPath, 'utf8')) : {};
  const today = new Date().toISOString().split('T')[0];
  usageByDay[today] = usageByDay[today] || 0;
  usageByDay[today] += Object.values(usagePerUser).reduce((sum, t) => sum + t, 0);
  fs.writeFileSync(usageByDayPath, JSON.stringify(usageByDay, null, 2));
  const usageTableHTML = Object.entries(usagePerUser).map(([user, tokens]) => `
    <tr><td>${user}</td><td>${tokens}</td><td><progress value="${tokens}" max="${userLimits[user] || 10000}"></progress></td></tr>
  `).join('');
  const totalUsed = Object.values(usageData).reduce((sum, val) => sum + val, 0);
  const creditLeft = 8.90;
  const limit = 120.0;
  const spentThisMonth = 16.52;
  const remaining = limit - totalUsed;

    const usageDays = Object.entries(usageByDay).slice(-7).map(([day, val]) => ({ date: day, tokens: val }));
  res.json({
    thisMonth: spentThisMonth,
    totalUsed,
    freeCreditsLeft: creditLeft,
    remaining,
    usagePerUser,
    usageByDay: usageDays
  });
});

app.post('/admin/reset-usage', authenticateJWT, (req, res) => {
  usageData = {};
  usagePerUser = {};
  saveUsage();
  saveUserUsage();
  logActivity('🧼 Manual reset of all usage');
  res.redirect('/usage');
});

app.post('/chat', authenticateJWT, async (req, res) => {
  const { messages, model } = req.body;
  const username = req.user?.username || 'anonymous';

  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Invalid request: messages missing or invalid' });
  }

  try {
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: model || 'gpt-4',
        messages,
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
        }
      }
    );

    const tokenUsed = response.data?.usage?.total_tokens || 0;
    usageData[username] = (usageData[username] || 0) + tokenUsed;
    usagePerUser[username] = (usagePerUser[username] || 0) + tokenUsed;

    const userLimit = userLimits[username] || 10000;
    if (usagePerUser[username] > userLimit) {
      logActivity(`⛔ ${username} exceeded limit (${userLimit} tokens)`);
      return res.status(429).json({ error: `Token usage limit exceeded (${userLimit}).` });
    }

    saveUsage();
    saveUserUsage();
    logActivity(`✅ ${username} | Tokens: ${tokenUsed} | Total: ${usageData[username]}`);

    res.json(response.data);
  } catch (err) {
    console.error('❌ GPT Error:', err.message);
    res.status(500).json({ error: 'GPT request failed', detail: err.message });
  }
});

cron.schedule('0 0 * * *', () => {
  usageData = {};
  saveUsage();
  requestsPerDay = {};
  saveRequestCount();
  logActivity('🧹 [AUTO] Daily usage and request count reset');
});

app.get('/admin-login.html', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Admin Login</title>
        <style>
          body { font-family: sans-serif; background: #222; color: #fff; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; }
          input, button { padding: 10px; margin: 10px; font-size: 1rem; }
        </style>
      </head>
      <body>
        <h2>🔐 Admin Login</h2>
        <input id="username" placeholder="Username" />
        <input id="password" type="password" placeholder="Password" />
        <button onclick="login()">Login & View Usage</button>
        <iframe id="usageFrame" style="width: 100%; max-width: 1000px; height: 600px; border: none; margin-top: 20px;"></iframe>
        <script>
          async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const res = await fetch('/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            if (data.token) {
              localStorage.setItem('jwt', data.token);
              document.getElementById('usageFrame').src = '/usage?token=' + data.token;
            } else {
              alert('Login failed');
            }
          }
        </script>
      </body>
    </html>
  `);
});

app.get('/usage-data', authenticateJWT, (req, res) => {
  const usageByDayPath = path.join(__dirname, 'usage_by_day.json');
  let usageByDay = fs.existsSync(usageByDayPath) ? JSON.parse(fs.readFileSync(usageByDayPath, 'utf8')) : {};
  const sorted = Object.entries(usageByDay)
    .sort(([a], [b]) => new Date(a) - new Date(b))
    .slice(-7)
    .map(([date, tokens]) => ({ date, tokens }));
  res.json(sorted);
});

const PORT = process.env.PORT || 3000;



