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
const PORT = process.env.PORT || 10001;

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
app.use((req, res, next) => {
  if (req.originalUrl === '/stripe/webhook') {
    bodyParser.raw({ type: 'application/json' })(req, res, next);
  } else {
    express.json({ limit: '15mb' })(req, res, next);
  }
});

// 🔁 Confirmation page that redirects based on payment record
app.get('/payment-confirmation', (req, res) => {
  const sessionId = req.query.session_id;
  const paymentsPath = path.join(__dirname, 'payments.json');

  if (!sessionId || !fs.existsSync(paymentsPath)) {
    return res.redirect('/error.html');
  }

  try {
    const payments = JSON.parse(fs.readFileSync(paymentsPath));
    const record = payments[sessionId];
    if (!record) return res.redirect('/error.html');

    const redirectPath = `/` + record.accessType + `/index.php?session_id=` + sessionId;
    return res.redirect(redirectPath);
  } catch (err) {
    return res.redirect('/error.html');
  }
});

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
  const { messages, max_tokens } = req.body;
  const ip = req.ip;
  const now = Date.now();
  const model = 'gpt-4o';

  if (!messages) return res.status(400).json({ error: 'Missing messages' });
  if (blockedIPs[ip] && blockedIPs[ip] > now) return res.status(403).json({ error: '⛔ Your IP is temporarily blocked.' });
  if (max_tokens && max_tokens > 1000) return res.status(400).json({ error: 'Max tokens limit exceeded.' });

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
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      { model, messages, max_tokens },
      { headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } }
    );

    const reply = response.data.choices?.[0]?.message?.content?.trim();

    if (!reply) {
      logActivity(`⚠️ Empty reply from OpenAI. Full response: ${JSON.stringify(response.data)}`);
      return res.json({ reply: '🤖 I couldn’t find a specific answer. Try asking differently or rephrasing your question.' });
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

app.post('/stripe/webhook', bodyParser.raw({ type: 'application/json' }), async (req, res) => {
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

    try {
      const fullSession = await stripe.checkout.sessions.retrieve(session.id, {
        expand: ['line_items.data.price.product'],
      });

      const lineItems = fullSession.line_items.data;
      const productName = lineItems?.[0]?.price?.product?.name || 'unknown';
      const email = session.customer_email || 'unknown';
      const expiresAt = Date.now() + 24 * 60 * 60 * 1000;

      const paymentsPath = path.join(__dirname, 'payments.json');
      let paymentData = fs.existsSync(paymentsPath) ? JSON.parse(fs.readFileSync(paymentsPath)) : {};

      const accessType = productName.toLowerCase().includes('helper') ? 'register-helper' : 'immigrant-login';

      paymentData[session.id] = {
        email,
        accessType,
        expiresAt
      };
      fs.writeFileSync(paymentsPath, JSON.stringify(paymentData, null, 2));

      const msg = `💰 Stripe Payment Successful!\n📧 ${email}\n🧾 Product: ${productName}\n🕒 Expires: ${new Date(expiresAt).toLocaleString()}\n➡️ Access: ${accessType}`;
      logActivity(`💰 Stripe payment | ${msg}`);
      await sendTelegramAlert(msg);

    } catch (err) {
      console.error('❌ Failed to expand session with product info:', err.message);
    }
  }

  res.status(200).send('✅ Webhook received');
});

const { queryGnm } = require("./gnm/gnm-query.js");
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
