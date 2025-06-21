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
const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET || 'verysecretjwtkey';
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const GPT_SECRET = process.env.GPT_SECRET;
const OPENAI_KEY = process.env.OPENAI_API_KEY;

app.use(cors());
app.use(express.json({ limit: '15mb' }));

// Storage
const usagePath = path.join(__dirname, 'usage.json');
const requestPath = path.join(__dirname, 'requests.json');
const blockedPath = path.join(__dirname, 'blocked.json');
const logPath = path.join(__dirname, 'proxy_log.txt');

let usageData = fs.existsSync(usagePath) ? JSON.parse(fs.readFileSync(usagePath, 'utf8')) : {};
let requestsPerDay = fs.existsSync(requestPath) ? JSON.parse(fs.readFileSync(requestPath, 'utf8')) : {};
let blockedIPs = fs.existsSync(blockedPath) ? JSON.parse(fs.readFileSync(blockedPath, 'utf8')) : {};

function saveJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}
function logActivity(msg) {
  fs.appendFileSync(logPath, `[${new Date().toISOString()}] ${msg}\n`);
}
async function sendTelegramAlert(msg) {
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: `🚨 Proxy Alert:\n${msg}`,
    });
  } catch (e) {
    console.error('❌ Telegram error:', e.message);
  }
}

// Rate limiting middleware
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: '⏱️ Too many requests. Try again soon.'
}));

// Auth
const users = [];
const setupUser = () => {
  const username = process.env.ADMIN_USER || 'admin';
  const password = process.env.ADMIN_PASS || 'secret';
  const hash = bcrypt.hashSync(password, 10);
  users.push({ username, passwordHash: hash });
};
setupUser();

function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(403).json({ error: 'Missing token' });
  try {
    const token = authHeader.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
}

// Secret protection middleware
function checkGPTSecret(req, res, next) {
  if (req.headers['x-secret'] !== GPT_SECRET) {
    logActivity(`🚫 Unauthorized secret from ${req.ip}`);
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
}

// Proxy route
app.post('/proxy', async (req, res) => {
  const ip = req.ip;
  const now = Date.now();

  if (blockedIPs[ip] && blockedIPs[ip] > now) {
    return res.status(403).json({ error: 'Blocked for abuse.' });
  }

  const { apiKey, messages, model } = req.body;
  if (!apiKey || !messages || !model) return res.status(400).json({ error: 'Missing fields.' });

  requestsPerDay[ip] = (requestsPerDay[ip] || 0) + 1;
  usageData[ip] = usageData[ip] || 0;

  if (requestsPerDay[ip] > 100) {
    blockedIPs[ip] = now + 86400000;
    saveJSON(blockedPath, blockedIPs);
    return res.status(429).json({ error: 'Blocked for 24h.' });
  }

  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions',
      { model, messages },
      { headers: { Authorization: `Bearer ${apiKey}` } });

    const used = response.data.usage?.total_tokens || 0;
    usageData[ip] += used;
    saveJSON(usagePath, usageData);
    saveJSON(requestPath, requestsPerDay);

    if (usageData[ip] > 5000) {
      blockedIPs[ip] = now + 86400000;
      saveJSON(blockedPath, blockedIPs);
      return res.status(429).json({ error: 'Token limit exceeded.' });
    }

    logActivity(`✅ ${ip} | Tokens: ${used} | Total: ${usageData[ip]}`);
    res.json(response.data);
  } catch (err) {
    logActivity(`❌ Proxy error ${ip}: ${err.message}`);
    res.status(500).json({ error: 'Proxy failed', details: err.message });
  }
});

// Protected /chat route
app.post('/chat', checkGPTSecret, async (req, res) => {
  const { messages, model } = req.body;
  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions',
      { model: model || 'gpt-4', messages },
      { headers: { Authorization: `Bearer ${OPENAI_KEY}` } });
    res.json({ reply: response.data.choices?.[0]?.message?.content || '' });
  } catch (err) {
    res.status(500).json({ error: 'Chat error', details: err.message });
  }
});

// Logs (JWT protected)
app.get('/logs', authenticateJWT, (req, res) => {
  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Log error.');
    res.send(data.split('\n').slice(-100).join('\n'));
  });
});

// Daily reset
cron.schedule('0 0 * * *', () => {
  usageData = {};
  requestsPerDay = {};
  saveJSON(usagePath, usageData);
  saveJSON(requestPath, requestsPerDay);
  logActivity('🔁 Daily usage reset');
});

app.listen(PORT, () => {
  console.log(`🛡️ Proxy Shield AI running on port ${PORT}`);
});

app.listen(PORT, () => {
  console.log(`✅ Proxy Shield AI running on port ${PORT}`);
});
