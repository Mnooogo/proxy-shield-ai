// ✅ Proxy Shield AI – GPT + Telegram + Stripe Webhook Version
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
const session = require('express-session');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 10000;

const JWT_SECRET = process.env.JWT_SECRET || 'verysecretjwtkey';
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const GPT_SECRET = process.env.GPT_SECRET;

let activeCodes = {};

app.use(session({
  secret: process.env.SESSION_SECRET || 'immigrant_secret_session_key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: false
  }
}));

app.use(cors());
// Raw body for Stripe only
app.use((req, res, next) => {
  if (req.originalUrl === '/stripe/webhook') {
    bodyParser.raw({ type: 'application/json' })(req, res, next);
  } else {
    express.json({ limit: '15mb' })(req, res, next);
  }
});


// File paths
const blockedPath = path.join(__dirname, 'blocked.json');
const usagePath = path.join(__dirname, 'usage.json');
const requestCountPath = path.join(__dirname, 'requests.json');
const logPath = path.join(__dirname, 'proxy_log.txt');

let blockedIPs = fs.existsSync(blockedPath) ? JSON.parse(fs.readFileSync(blockedPath)) : {};
let usageData = fs.existsSync(usagePath) ? JSON.parse(fs.readFileSync(usagePath)) : {};
let requestsPerDay = fs.existsSync(requestCountPath) ? JSON.parse(fs.readFileSync(requestCountPath)) : {};

function saveBlocked() { fs.writeFileSync(blockedPath, JSON.stringify(blockedIPs, null, 2)); }
function saveUsage() { fs.writeFileSync(usagePath, JSON.stringify(usageData, null, 2)); }
function saveRequestCount() { fs.writeFileSync(requestCountPath, JSON.stringify(requestsPerDay, null, 2)); }

function logActivity(entry) {
  const logEntry = `[${new Date().toISOString()}] ${entry}\n`;
  fs.appendFileSync(logPath, logEntry);
}

async function sendTelegramAlert(msg) {
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: msg,
    });
  } catch (err) {
    console.error('❌ Telegram alert failed:', err.message);
  }
}

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: '⚠️ Too many requests from this IP, please try again later.'
});
app.use(limiter);

function checkGPTSecret(req, res, next) {
  const secret = req.headers['x-secret'];
  if (!secret || secret !== GPT_SECRET) {
    logActivity(`🚫 Unauthorized access to ${req.originalUrl} from ${req.ip}`);
    return res.status(403).json({ error: 'Unauthorized – invalid GPT secret.' });
  }
  next();
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
  } catch {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

app.get('/logs', authenticateJWT, (req, res) => {
  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Error reading log.');
    res.send(data.split('\n').slice(-100).join('\n'));
  });
});

app.get('/token-stats', authenticateJWT, (req, res) => {
  res.json(usageData);
});

app.post('/chat', checkGPTSecret, async (req, res) => {
  const { messages, max_tokens, vector_namespace } = req.body;
  const ip = req.ip;
  const now = Date.now();
  const model = 'gpt-3.5-turbo';

  if (!messages) return res.status(400).json({ error: 'Missing messages' });
  if (blockedIPs[ip] && blockedIPs[ip] > now) return res.status(403).json({ error: '⛔ Your IP is temporarily blocked.' });

  const dailyTotal = Object.values(usageData).reduce((a, b) => a + b, 0);
  if (dailyTotal > 150000) return res.status(429).json({ error: 'Site-wide token limit reached for today.' });

  const timestamps = requestsPerDay[ip] || [];
  timestamps.push(now);
  requestsPerDay[ip] = timestamps.filter(ts => now - ts < 10000);
  if (requestsPerDay[ip].length > 5) {
    const alertMsg = `🚨 Suspicious activity from ${ip} – ${timestamps.length} requests in 10s`;
    logActivity(alertMsg);
    sendTelegramAlert(alertMsg);
  }

  try {
    let reply = "No response";

    // 🧠 Ако идва заявка за GNM, пусни query към GNM vector база
    if (vector_namespace === "gnm") {
      const userMessage = messages.find(m => m.role === "user")?.content || "No question";
      reply = await queryGnm(userMessage);
    } else {
      const response = await axios.post('https://api.openai.com/v1/chat/completions',
        { model, messages, max_tokens },
        { headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } });
      reply = response.data.choices[0]?.message?.content?.trim();
    }

    const tokenUsed = response.data?.usage?.total_tokens || 0;
    usageData[ip] = (usageData[ip] || 0) + tokenUsed;
    saveUsage();

    if (usageData[ip] > 10000) {
      blockedIPs[ip] = now + 86400000;
      saveBlocked();
      logActivity(`⛔ IP ${ip} blocked (token abuse in /chat)`);
      return res.status(429).json({ error: 'Blocked for 24h due to token overuse.' });
    }

    logActivity(`🗨️ /chat by ${ip} | Tokens: ${tokenUsed} | Total: ${usageData[ip]}`);
    res.json({ reply });
  } catch (err) {
    logActivity(`❌ /chat error for ${ip} | ${err.message}`);
    res.status(500).json({ error: 'Chat error', details: err.message });
  }
});

cron.schedule('0 0 * * *', () => {
  usageData = {};
  requestsPerDay = {};
  saveUsage();
  saveRequestCount();
  logActivity('🔁 Daily reset of usage and request count.');
});

app.post('/send-code', async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) return res.status(400).json({ success: false, message: 'Phone number required.' });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  activeCodes[phoneNumber] = code;
  await sendTelegramAlert(`📬 Access code for ${phoneNumber}: ${code}`);
  logActivity(`📬 Code ${code} generated for ${phoneNumber}`);
  res.json({ success: true });
});

app.post('/verify-code', async (req, res) => {
  const { phoneNumber, code } = req.body;
  if (!phoneNumber || !code) return res.status(400).json({ success: false, message: 'Missing phone or code.' });
  if (activeCodes[phoneNumber] === code) {
    delete activeCodes[phoneNumber];
    req.session.verified = true;
    await sendTelegramAlert(`✅ Code verified for ${phoneNumber}`);
    logActivity(`✅ Verified code for ${phoneNumber}`);
    return res.json({ success: true });
  }
  await sendTelegramAlert(`❌ Invalid code "${code}" for ${phoneNumber}`);
  logActivity(`❌ Invalid code "${code}" for ${phoneNumber}`);
  res.status(401).json({ success: false, message: 'Invalid or expired code.' });
});

// ✅ Stripe Webhook Endpoint
app.post('/stripe/webhook', bodyParser.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('⚠️ Webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const msg = `💰 Stripe Payment Successful!\n✅ Email: ${session.customer_email || 'unknown'}\n🧾 Amount: ${session.amount_total / 100} ${session.currency.toUpperCase()}`;
    logActivity(`💰 Stripe payment: ${msg}`);
    sendTelegramAlert(msg);
  }

  res.status(200).send('✅ Webhook received');
});
const { queryGnm } = require('./gnm/gnm-query');

app.post('/gnm-query', checkGPTSecret, async (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: 'Missing query input.' });

  try {
    const result = await queryGnm(query);
    res.json({ result });
  } catch (err) {
    logActivity(`❌ GNM query failed: ${err.message}`);
    res.status(500).json({ error: 'GNM query failed', details: err.message });
  }
});



app.listen(PORT, () => {
  console.log(`✅ Proxy Shield AI running on port ${PORT}`);
});
