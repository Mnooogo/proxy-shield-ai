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

    const redirectPath = `/${record.accessType}/index.php?session_id=${sessionId}`;
    return res.redirect(redirectPath);
  } catch (err) {
    return res.redirect('/error.html');
  }
});

const logPath = path.join(__dirname, 'proxy_log.txt');
const usagePath = path.join(__dirname, 'usage.json');
const requestCountPath = path.join(__dirname, 'requests.json');
let blockedIPs = fs.existsSync(path.join(__dirname, 'blocked.json')) ? JSON.parse(fs.readFileSync(path.join(__dirname, 'blocked.json'))) : {};
let usageData = fs.existsSync(usagePath) ? JSON.parse(fs.readFileSync(usagePath)) : {};
let requestsPerDay = fs.existsSync(requestCountPath) ? JSON.parse(fs.readFileSync(requestCountPath)) : {};

function saveBlocked() { fs.writeFileSync(path.join(__dirname, 'blocked.json'), JSON.stringify(blockedIPs, null, 2)); }
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

// ✅ Stripe Webhook Update with line item parsing for accessType
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
    const paymentsPath = path.join(__dirname, 'payments.json');

    stripe.checkout.sessions.listLineItems(session.id, {}, async (err, lineItems) => {
      if (err) {
        console.error('❌ Error retrieving line items:', err);
        return;
      }

      const productName = lineItems.data[0]?.description || 'Immigrant Login';
      const accessType = productName.toLowerCase().includes('helper') ? 'immigrant-helper' : 'immigrant-login';

      let payments = fs.existsSync(paymentsPath) ? JSON.parse(fs.readFileSync(paymentsPath)) : {};
      payments[session.id] = { accessType };
      fs.writeFileSync(paymentsPath, JSON.stringify(payments, null, 2));

      const msg = `💰 Stripe Payment Successful!\n✅ Email: ${session.customer_email || 'unknown'}\n🧾 Amount: ${session.amount_total / 100} ${session.currency.toUpperCase()}\n🔁 Access: ${accessType}`;
      logActivity(`💰 Stripe payment: ${msg}`);
      sendTelegramAlert(msg);
    });
  }

  res.status(200).send('✅ Webhook received');
});
