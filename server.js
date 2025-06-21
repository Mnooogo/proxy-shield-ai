// ✅ Full Proxy Shield AI server.js with ALL protections and logic integrated
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
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'verysecretjwtkey';
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const GPT_SECRET = process.env.GPT_SECRET;

app.use(cors());
app.use(express.json({ limit: '15mb' }));

const blockedPath = path.join(__dirname, 'blocked.json');
let blockedIPs = fs.existsSync(blockedPath) ? JSON.parse(fs.readFileSync(blockedPath, 'utf8')) : {};
function saveBlocked() { fs.writeFileSync(blockedPath, JSON.stringify(blockedIPs, null, 2)); }

const usagePath = path.join(__dirname, 'usage.json');
let usageData = fs.existsSync(usagePath) ? JSON.parse(fs.readFileSync(usagePath, 'utf8')) : {};
function saveUsage() { fs.writeFileSync(usagePath, JSON.stringify(usageData, null, 2)); }

const requestCountPath = path.join(__dirname, 'requests.json');
let requestsPerDay = fs.existsSync(requestCountPath) ? JSON.parse(fs.readFileSync(requestCountPath, 'utf8')) : {};
function saveRequestCount() { fs.writeFileSync(requestCountPath, JSON.stringify(requestsPerDay, null, 2)); }

const logPath = path.join(__dirname, 'proxy_log.txt');
function logActivity(entry) {
  const logEntry = `[${new Date().toISOString()}] ${entry}\n`;
  fs.appendFileSync(logPath, logEntry);
}

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: '⚠️ Too many requests from this IP, please try again later.'
});
app.use(limiter);

const ipTimestamps = {};

function checkGPTSecret(req, res, next) {
  const secret = req.headers['x-secret'];
  if (!secret || secret !== GPT_SECRET) {
    logActivity(`🚫 Unauthorized access to ${req.originalUrl} from ${req.ip}`);
    return res.status(403).json({ error: 'Unauthorized – invalid GPT secret.' });
  }
  next();
}

async function sendTelegramAlert(msg) {
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: `🚨 Proxy Alert:\n${msg}`,
    });
  } catch (err) {
    console.error('❌ Telegram alert failed:', err.message);
  }
}

const users = [];
const setupUser = () => {
  const username = process.env.ADMIN_USER || 'adminSTEF';
  const rawPass = process.env.ADMIN_PASS || 'VetomEmka21$$$';
  const hash = bcrypt.hashSync(rawPass, 10);
  users.push({ username, passwordHash: hash });
};
setupUser();

function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(403).json({ error: 'Invalid token' });
  try {
    const token = authHeader.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

app.get('/logs', authenticateJWT, (req, res) => {
  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Error reading log.');
    res.send(data.split('\n').slice(-100).join('\n'));
  });
});

// ✅ Full proxy endpoint for external clients
app.post('/proxy', async (req, res) => {
  const ip = req.ip;
  const now = Date.now();

  if (blockedIPs[ip] && blockedIPs[ip] > now) {
    logActivity(`⛔ BLOCKED: ${ip} tried to access during ban`);
    return res.status(403).json({ error: 'Your IP is temporarily blocked.' });
  } else if (blockedIPs[ip] && blockedIPs[ip] <= now) {
    delete blockedIPs[ip];
    saveBlocked();
  }

  const { apiKey, messages, model } = req.body;
  if (!apiKey || !messages || !model) {
    logActivity(`Invalid request from ${ip}`);
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  requestsPerDay[ip] = (requestsPerDay[ip] || 0) + 1;
  saveRequestCount();

  if (requestsPerDay[ip] > 100) {
    blockedIPs[ip] = now + 24 * 60 * 60 * 1000;
    saveBlocked();
    logActivity(`⛔ IP ${ip} blocked for exceeding daily request limit`);
    return res.status(429).json({ error: 'You have been temporarily blocked for 24 hours.' });
  }

  ipTimestamps[ip] = ipTimestamps[ip] || [];
  ipTimestamps[ip].push(now);
  ipTimestamps[ip] = ipTimestamps[ip].filter(ts => now - ts < 10000);

  if (ipTimestamps[ip].length > 5) {
    const alertMsg = `🚨 Suspicious activity from ${ip} – ${ipTimestamps[ip].length} requests in 10s`;
    logActivity(alertMsg);
    sendTelegramAlert(alertMsg);
  }

  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions',
      { model, messages },
      { headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' } });

    const tokenUsed = response.data?.usage?.total_tokens || 0;
    usageData[ip] = (usageData[ip] || 0) + tokenUsed;
    saveUsage();

    if (usageData[ip] > 5000) {
      blockedIPs[ip] = now + 24 * 60 * 60 * 1000;
      saveBlocked();
      logActivity(`⛔ IP ${ip} blocked for exceeding token limit`);
      return res.status(429).json({ error: 'Token limit exceeded. Blocked 24h.' });
    }

    logActivity(`✅ ${ip} | Tokens: ${tokenUsed} | Total: ${usageData[ip]}`);
    if (!res.headersSent) res.json(response.data);
  } catch (err) {
    logActivity(`❌ Proxy error for ${ip} | ${err.message}`);
    if (!res.headersSent) res.status(500).json({ error: 'Proxy error', details: err.message });
  }
});

// ✅ Protected /chat endpoint
app.post('/chat', checkGPTSecret, async (req, res) => {
  const { messages, model } = req.body;
  if (!messages) return res.status(400).json({ error: 'Missing messages' });

  const ip = req.ip;
  const selectedModel = model || 'gpt-4';
  const now = Date.now();

  if (blockedIPs[ip] && blockedIPs[ip] > now) {
    return res.status(403).json({ error: '⛔ Your IP is temporarily blocked.' });
  }

  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions',
      { model: selectedModel, messages },
      { headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' } });

    const reply = response.data.choices[0]?.message?.content || 'No reply generated.';
    const tokenUsed = response.data?.usage?.total_tokens || 0;

    usageData[ip] = (usageData[ip] || 0) + tokenUsed;
    saveUsage();

    if (usageData[ip] > 5000) {
      blockedIPs[ip] = now + 24 * 60 * 60 * 1000;
      saveBlocked();
      logActivity(`⛔ IP ${ip} blocked (token abuse in /chat)`);
      return res.status(429).json({ error: 'Blocked for 24h due to token overuse.' });
    }

    logActivity(`🗨️ /chat by ${ip} | Tokens: ${tokenUsed} | Total: ${usageData[ip]}`);
    if (!res.headersSent) res.json({ reply });
  } catch (err) {
    logActivity(`❌ /chat error for ${ip} | ${err.message}`);
    if (!res.headersSent) res.status(500).json({ error: 'Chat error', details: err.message });
  }
});

app.post('/api/vision', checkGPTSecret, async (req, res) => {
  const { imageBase64 } = req.body;
  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: 'You are a material expert. Identify the material in the image.' },
        {
          role: 'user',
          content: [ { type: 'image_url', image_url: { url: `data:image/jpeg;base64,${imageBase64}` } } ]
        }
      ],
      max_tokens: 100
    }, {
      headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` }
    });
    if (!res.headersSent) res.json(response.data);
  } catch (error) {
    console.error('❌ Vision API error:', error.message);
    if (!res.headersSent) res.status(500).json({ error: 'Vision API failed' });
  }
});

cron.schedule('0 0 * * *', () => {
  usageData = {};
  requestsPerDay = {};
  saveUsage();
  saveRequestCount();
  logActivity('🔁 Daily reset of usage and request count.');
});

app.listen(PORT, () => {
  console.log(`✅ Proxy Shield AI running on port ${PORT}`);
});
