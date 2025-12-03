require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { analyzeText } = require('./live-interface-core');

const app = express();
app.set('trust proxy', true);

// === Environment variables ===
const PORT = parseInt(process.env.PORT, 10) || 8080;
const JWT_SECRET = process.env.JWT_SECRET;
const GPT_SECRET = process.env.GPT_SECRET;
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const OPENAI_KEY = process.env.OPENAI_API_KEY;
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'https://doagift.shop';

// === Middleware ===
app.use(
  cors({
    origin: CORS_ORIGIN,
    methods: ['GET', 'POST'],
    credentials: true,
  })
);
app.use(express.json({ limit: '15mb' }));
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    message: '⏱️ Too many requests. Try again later.',
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// === File paths ===
const usagePath = path.join(__dirname, 'usage.json');
const requestPath = path.join(__dirname, 'requests.json');
const blockedPath = path.join(__dirname, 'blocked.json');
const logPath = path.join(__dirname, 'proxy_log.txt');
const memoryDir = path.join(__dirname, 'memory');

// === Load or create storage ===
let usageData = fs.existsSync(usagePath)
  ? JSON.parse(fs.readFileSync(usagePath))
  : {};
let requestsPerDay = fs.existsSync(requestPath)
  ? JSON.parse(fs.readFileSync(requestPath))
  : {};
let blockedIPs = fs.existsSync(blockedPath)
  ? JSON.parse(fs.readFileSync(blockedPath))
  : {};

const saveJSON = (file, data) =>
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
const log = (msg) =>
  fs.appendFileSync(logPath, `[${new Date().toISOString()}] ${msg}\n`);

// === Telegram notifications ===
async function sendTelegramAlert(msg) {
  if (!TELEGRAM_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: `📢 Proxy:\n${msg}`,
    });
  } catch (e) {
    console.error('❌ Telegram error:', e.message);
  }
}

// === Admin credentials ===
const users = [];
function setupUser() {
  const username = process.env.ADMIN_USER || 'admin';
  const password = process.env.ADMIN_PASS || 'secret';
  const hash = bcrypt.hashSync(password, 10);
  users.push({ username, passwordHash: hash });
}
setupUser();

// === JWT Authentication ===
function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(403).json({ error: 'Missing token' });
  try {
    const token = authHeader.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: 'Invalid token' });
  }
}

// === GPT Secret check ===
function checkGPTSecret(req, res, next) {
  if (req.headers['x-secret'] !== GPT_SECRET) {
    log(`🚫 Unauthorized secret from ${req.ip}`);
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
}

// === Routes ===
app.get('/', (_, res) => res.json({ status: '✅ Proxy Shield Active' }));

// === Chat endpoint ===
app.post('/chat', checkGPTSecret, async (req, res) => {
  const { messages, model } = req.body;

  try {
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      { model: model || 'gpt-3.5-turbo', messages },
      { headers: { Authorization: `Bearer ${OPENAI_KEY}` } }
    );

    const reply = response.data?.choices?.[0]?.message?.content;
    if (!reply) throw new Error('Invalid OpenAI response');

    res.json({ reply, usage: response.data.usage || {} });
    log(`✅ /chat used | Tokens: ${response.data.usage?.total_tokens || 0}`);
  } catch (err) {
    console.error('❌ Chat error:', err.response?.data || err.message);
    log(`❌ Chat error: ${err.message}`);
    res.status(500).json({ error: 'Chat error', details: err.message });
  }
});

// === Living Interface ===
app.post('/living-interface', checkGPTSecret, async (req, res) => {
  const { text, model } = req.body;
  if (!text || typeof text !== 'string')
    return res.status(400).json({ error: 'Missing or invalid text' });

  const analysis = analyzeText(text);
  const prompt = `
You are a prototype of a "Living Interface" between human and AI.
User's state:
- Rhythm: pace = ${analysis.rhythm.pace}, density = ${analysis.rhythm.density}, length = ${analysis.rhythm.length} words
- Emotion: tone = ${analysis.emo.tone}, intensity = ${analysis.emo.intensity}
- Concepts: ${analysis.concepts.length ? analysis.concepts.join(', ') : 'none detected'}

Instruction:
Respond in Bulgarian.
First reflect the user's state (1–2 изречения), then continue naturally.

Original user text:
"${text}"
  `.trim();

  try {
    const response = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: model || 'gpt-3.5-turbo',
        messages: [
          { role: 'system', content: 'You are the Living Interface.' },
          { role: 'user', content: prompt },
        ],
      },
      { headers: { Authorization: `Bearer ${OPENAI_KEY}` } }
    );

    const reply = response.data?.choices?.[0]?.message?.content;
    if (!reply) throw new Error('Invalid OpenAI response');

    log(`✅ /living-interface used | Tokens: ${response.data.usage?.total_tokens || 0}`);
    return res.json({ analysis, reply, usage: response.data.usage || {} });
  } catch (err) {
    console.error('❌ Living interface error:', err.response?.data || err.message);
    log(`❌ Living interface error: ${err.message}`);
    return res.status(500).json({ error: 'Living interface error', details: err.message });
  }
});

// === Save/load memory ===
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
  const memory = fs.existsSync(memoryPath)
    ? fs.readFileSync(memoryPath, 'utf8')
    : '';
  res.json({ memory });
});

// === SMS / Verification codes ===
const verificationCodes = {};

app.post('/send-code', async (req, res) => {
  const { phoneNumber, source = 'unknown' } = req.body;
  if (!phoneNumber)
    return res.status(400).json({ success: false, error: 'Missing phoneNumber' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 10 * 60 * 1000;
  verificationCodes[phoneNumber] = { code, expires };

  const msg = `📨 Code for ${phoneNumber} from [${source}]: ${code}`;
  log(msg);
  await sendTelegramAlert(msg);
  res.json({ success: true });
});

app.post('/verify-code', (req, res) => {
  const { phoneNumber, code, source = 'unknown' } = req.body;
  if (!phoneNumber || !code)
    return res.status(400).json({ success: false, error: 'Missing phone or code' });

  const record = verificationCodes[phoneNumber];
  if (!record)
    return res.json({ success: false, error: 'No code found' });

  if (Date.now() > record.expires) {
    delete verificationCodes[phoneNumber];
    return res.json({ success: false, error: 'Code expired' });
  }

  if (record.code !== code)
    return res.json({ success: false, error: 'Invalid code' });

  delete verificationCodes[phoneNumber];
  sendTelegramAlert(`✅ Verified: ${phoneNumber} from [${source}]`);
  res.json({ success: true });
});

// === Start server ===
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Proxy Shield running on port ${PORT}`);
});
