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
const PORT = 3000;
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

const requestCountPath = path.join(__dirname, 'requests.json');
let requestsPerDay = fs.existsSync(requestCountPath)
  ? JSON.parse(fs.readFileSync(requestCountPath, 'utf8'))
  : {};
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
const setupUser = () => {
  const username = process.env.ADMIN_USER || 'admin';
  const rawPass = process.env.ADMIN_PASS || 'password';
  const hash = bcrypt.hashSync(rawPass, 10);
  users.push({ username, passwordHash: hash });
};
setupUser();
console.log('[DEBUG] Current users:', users);

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    logActivity(`❌ Failed login attempt: ${username}`);
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '2h' });
  logActivity(`✅ Login success: ${username}`);
  res.json({ success: true, token });
});

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

app.get('/logs', authenticateJWT, (req, res) => {
  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Error reading log file.');
    const lines = data.split('\n');
    const last100 = lines.slice(-100).join('\n');
    res.send(last100);
  });
});

app.delete('/logs', authenticateJWT, (req, res) => {
  fs.writeFile(logPath, '', (err) => {
    if (err) {
      console.error('❌ Failed to clear logs:', err);
      return res.status(500).json({ error: 'Failed to clear logs' });
    }
    logActivity('Logs cleared manually');
    res.json({ message: 'Logs cleared' });
  });
});

app.get('/logs/json', authenticateJWT, (req, res) => {
  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Error reading log file.');
    const lines = data.split('\n').filter(Boolean);
    const entries = lines.map(line => {
      const match = line.match(/^\[(.*?)\] (.*)$/);
      return match ? { timestamp: match[1], entry: match[2] } : null;
    }).filter(Boolean);
    res.json(entries);
  });
});

app.get('/request-counts', authenticateJWT, (req, res) => {
  res.json(requestsPerDay);
});

app.delete('/usage', authenticateJWT, (req, res) => {
  usageData = {};
  saveUsage();
  logActivity('🧹 Usage data manually reset by admin.');
  res.json({ message: 'Usage data reset successfully.' });
});

cron.schedule('0 0 * * *', () => {
  usageData = {};
  saveUsage();
  logActivity('🧹 [AUTO] Usage data reset at 00:00');
  requestsPerDay = {};
  saveRequestCount();
  logActivity('🧹 [AUTO] Request count reset at 00:00');
});

app.listen(PORT, () => {
  console.log(`🛡 Proxy Shield AI running on http://localhost:${PORT}`);
  logActivity('Proxy server started');
});
