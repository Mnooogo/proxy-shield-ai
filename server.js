// ✅ Proxy Shield AI – Stripe-only version
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const cron = require('node-cron');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 10000;

const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const GPT_SECRET = process.env.GPT_SECRET;
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_SECRET;

app.use(cors());
app.use(express.json({ limit: '15mb' }));

// Webhook requires raw body
app.post('/stripe/webhook', bodyParser.raw({ type: 'application/json' }));

// Paths for logging
const usagePath = path.join(__dirname, 'usage.json');
const logPath = path.join(__dirname, 'proxy_log.txt');
let usageData = fs.existsSync(usagePath) ? JSON.parse(fs.readFileSync(usagePath)) : {};

function saveUsage() { fs.writeFileSync(usagePath, JSON.stringify(usageData, null, 2)); }
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

// Rate limiter
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

// ✅ GPT endpoint
app.post('/chat', checkGPTSecret, async (req, res) => {
  const { messages, max_tokens } = req.body;
  const ip = req.ip;
  const model = 'gpt-3.5-turbo';

  if (!messages) return res.status(400).json({ error: 'Missing messages' });

  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions',
      { model, messages, max_tokens },
      { headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } });

    const reply = response.data.choices[0]?.message?.content || 'No reply generated.';
    const tokenUsed = response.data?.usage?.total_tokens || 0;

    usageData[ip] = (usageData[ip] || 0) + tokenUsed;
    saveUsage();
    logActivity(`🗨️ /chat by ${ip} | Tokens: ${tokenUsed}`);

    res.json({ reply });
  } catch (err) {
    logActivity(`❌ /chat error for ${ip} | ${err.message}`);
    res.status(500).json({ error: 'Chat error', details: err.message });
  }
});

// ✅ Stripe Webhook for payment verification
const stripe = require('stripe')(STRIPE_SECRET_KEY);
app.post('/stripe/webhook', bodyParser.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('❌ Webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const clientReferenceId = session.client_reference_id || 'unknown';
    logActivity(`💳 Payment verified – Access granted to ${clientReferenceId}`);
    sendTelegramAlert(`✅ Stripe payment confirmed for ${clientReferenceId}`);
  }

  res.json({ received: true });
});

// ✅ Daily reset at midnight
cron.schedule('0 0 * * *', () => {
  usageData = {};
  saveUsage();
  logActivity('🔁 Daily token usage reset');
});

app.listen(PORT, () => {
  console.log(`✅ Proxy Shield AI listening on port ${PORT}`);
});
