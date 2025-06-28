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
app.set('trust proxy', true);

const PORT = parseInt(process.env.PORT, 10) || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const GPT_SECRET = process.env.GPT_SECRET;
const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const OPENAI_KEY = process.env.OPENAI_API_KEY;

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: '⏱️ Too many requests. Try again later.',
  standardHeaders: true,
  legacyHeaders: false
}));

const usagePath = path.join(__dirname, 'usage.json');
const requestPath = path.join(__dirname, 'requests.json');
const blockedPath = path.join(__dirname, 'blocked.json');
const logPath = path.join(__dirname, 'proxy_log.txt');
const memoryDir = path.join(__dirname, 'memory');

let usageData = fs.existsSync(usagePath) ? JSON.parse(fs.readFileSync(usagePath)) : {};
let requestsPerDay = fs.existsSync(requestPath) ? JSON.parse(fs.readFileSync(requestPath)) : {};
let blockedIPs = fs.existsSync(blockedPath) ? JSON.parse(fs.readFileSync(blockedPath)) : {};

const saveJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));
const log = msg => fs.appendFileSync(logPath, `[${new Date().toISOString()}] ${msg}\n`);

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

app.get('/', (_, res) => res.json({ status: '✅ Proxy Shield Active' }));

app.post('/chat', checkGPTSecret, async (req, res) => {
  const { messages, model } = req.body;

  try {
    const response = await axios.post('https://api.openai.com/v1/chat/completions',
      {
        model: model || 'gpt-3.5-turbo',
        messages,
      },
      {
        headers: {
          Authorization: `Bearer ${OPENAI_KEY}`,
        },
      });

    if (!response.data || !response.data.choices || !response.data.choices[0]) {
      log('❌ Invalid response from OpenAI');
      return res.status(500).json({ error: 'Invalid response from OpenAI' });
    }

    const reply = response.data.choices[0].message.content;
    res.json({
      reply,
      usage: response.data.usage || {}
    });

    log(`✅ /chat used | Tokens: ${response.data.usage?.total_tokens || 0}`);
  } catch (err) {
    log(`❌ Chat error: ${err.message}`);
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

app.post('/send-code', async (req, res) => {
  const { phoneNumber, source = 'unknown' } = req.body;

  if (!phoneNumber) return res.status(400).json({ success: false, error: 'Missing phoneNumber' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 10 * 60 * 1000;

  verificationCodes[phoneNumber] = { code, expires };

  const msg = `📨 Code for ${phoneNumber} from [${source}]: ${code}`;
  log(msg);
  await sendTelegramAlert(msg);

  res.json({ success: true });
});

const verificationCodes = {};

app.post('/verify-code', (req, res) => {
  const { phoneNumber, code, source = 'unknown' } = req.body;

  if (!phoneNumber || !code) {
    return res.status(400).json({ success: false, error: 'Missing phone or code' });
  }

  const record = verificationCodes[phoneNumber];

  if (!record) {
    log(`❌ No code found for ${phoneNumber} (${source})`);
    return res.json({ success: false, error: 'No code found' });
  }

  if (Date.now() > record.expires) {
    delete verificationCodes[phoneNumber];
    log(`⏰ Code expired for ${phoneNumber} (${source})`);
    return res.json({ success: false, error: 'Code expired' });
  }

  if (record.code !== code) {
    log(`❌ Invalid code for ${phoneNumber} (${source})`);
    return res.json({ success: false, error: 'Invalid code' });
  }

  delete verificationCodes[phoneNumber];
  log(`✅ Code verified for ${phoneNumber} (${source})`);
  sendTelegramAlert(`✅ Verified: ${phoneNumber} from [${source}]`);

  res.json({ success: true });
});

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Proxy Shield running on port ${PORT}`);
});
