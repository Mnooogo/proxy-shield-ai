// ✅ Добавено към Proxy Shield API
const express = require('express');
const plivo = require('plivo');
const router = express.Router();

// 🔐 Plivo ключове – използвай .env
const client = new plivo.Client(process.env.PLIVO_AUTH_ID, process.env.PLIVO_AUTH_TOKEN);

// 🗂️ Временно съхранение на кодове (по телефон)
let smsCodes = {}; // Пример: { "+359888123456": "723849" }

// 📤 Изпрати SMS
router.post('/sms/send', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ success: false, error: 'Missing phone number' });

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  smsCodes[phone] = code;

  try {
    await client.messages.create(
      process.env.PLIVO_SENDER_NUMBER, // От кой номер
      phone,                            // До кой номер
      `Your Immigrant Login Code is: ${code}`
    );
    res.json({ success: true, message: 'SMS sent successfully' });
  } catch (err) {
    console.error('Plivo error:', err);
    res.status(500).json({ success: false, error: 'Failed to send SMS' });
  }
});

// ✅ Потвърди код
router.post('/sms/verify', (req, res) => {
  const { phone, code } = req.body;
  if (!phone || !code) return res.status(400).json({ success: false, error: 'Missing data' });

  if (smsCodes[phone] === code) {
    delete smsCodes[phone];
    res.json({ success: true, message: 'Code verified – access granted' });
  } else {
    res.json({ success: false, message: 'Invalid code' });
  }
});

module.exports = router;

// В твоя main server.js:
// const smsRoutes = require('./sms-routes');
// app.use('/api', smsRoutes);
