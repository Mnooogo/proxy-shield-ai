// ✅ Stable Proxy Shield server.js
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', true); // ✅ Allow X-Forwarded-For

const PORT = parseInt(process.env.PORT, 10);
if (isNaN(PORT)) {
  console.error('❌ Invalid PORT:', process.env.PORT);
  process.exit(1);
}

// ENV CONFIG
const JWT_SECRET = process.env.JWT_SECRET;
const GPT_SECRET = process.env.GPT_SECRET;
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const OPENAI_KEY = process.env.OPENAI_API_KEY;

// Middleware
app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: '⏱️ Too many requests. Try again soon.'
}));

// Paths
const usagePath = path.join(__dirname, 'usage.json');
const requestPath = path.join(__dirname, 'requests.json');
const blockedPath = path.join(__dirname, 'blocked.json');
const logPath = path.join(__dirname, 'proxy_log.txt');
const memoryDir = path.join(__dirname, 'memory');

// Data storage
let usageData = fs.existsSync(usagePath) ? JSON.parse(fs.readFileSync(usagePath)) : {};
let requestsPerDay = fs.existsSync(requestPath) ? JSON.parse(fs.readFileSync(requestPath)) : {};
let blockedIPs = fs.existsSync(blockedPath) ? JSON.parse(fs.readFileSync(blockedPath)) : {};

const saveJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));
const log = msg => fs.appendFileSync(logPath, `[${new Date().toISOString()}] ${msg}\n`);

// Telegram alert
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

function checkGPTSecret(req, res, next) {
  if (req.headers['x-secret'] !== GPT_SECRET) {
    log(`🚫 Unauthorized secret from ${req.ip}`);
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
}

// Routes
app.get('/', (_, res) => res.json({ status: '🛡️ Proxy Shield Ready' }));

app.post('/proxy', async (req, res) => {
  const ip = req.ip;
  const now = Date.now();
  const { apiKey, messages, model } = req.body;

  if (blockedIPs[ip] && blockedIPs[ip] > now) return res.status(403).json({ error: 'Blocked for abuse.' });
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

    log(`✅ ${ip} | Tokens: ${used} | Total: ${usageData[ip]}`);
    res.json(response.data);
  } catch (err) {
    log(`❌ Proxy error ${ip}: ${err.message}`);
    res.status(500).json({ error: 'Proxy failed', details: err.message });
  }
});

app.post('/chat', checkGPTSecret, async (req, res) => {
  const { messages, model } = req.body;
  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions',
      { model: model || 'gpt-3.5-turbo', messages },
      { headers: { Authorization: `Bearer ${OPENAI_KEY}` } });
    res.json({ reply: response.data.choices?.[0]?.message?.content || '' });
  } catch (err) {
    res.status(500).json({ error: 'Chat error', details: err.message });
  }
});

app.post('/save-memory', (req, res) => {
  const { userId, memory } = req.body;
  if (!userId) return res.status(400).json({ error: 'Missing userId' });

  fs.mkdirSync(memoryDir, { recursive: true });
  fs.writeFileSync(path.join(memoryDir, `${userId}.txt`), memory || '', 'utf8');

  res.json({ status: '✅ Memory saved to server.' });
});

app.post('/load-memory', (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'Missing userId' });

  const memoryPath = path.join(memoryDir, `${userId}.txt`);
  const memory = fs.existsSync(memoryPath) ? fs.readFileSync(memoryPath, 'utf8') : '';
  res.json({ memory });
});

// Error handler
app.use((err, req, res, next) => {
  console.error("🔥 Global Error Handler:", err);
  if (!res.headersSent) {
    res.status(500).json({ error: err.message || 'Internal Server Error' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Proxy Shield AI running on port ${PORT} on 0.0.0.0`);
});
