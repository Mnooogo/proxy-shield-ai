const fs = require('fs');
const pdfParse = require('pdf-parse');
const path = require('path');

const gnmPdfPath = path.join(__dirname, 'gnm-info.pdf');

async function queryGnm(query) {
  if (!fs.existsSync(gnmPdfPath)) {
    throw new Error('GNM PDF not found.');
  }

  const dataBuffer = fs.readFileSync(gnmPdfPath);
  const data = await pdfParse(dataBuffer);

  const text = data.text.toLowerCase();
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);

  const results = lines.filter(line => line.includes(query.toLowerCase()));

  if (results.length === 0) {
    return '❌ No relevant information found in GNM PDF.';
  }

  return results.slice(0, 10).join('\n');
}

module.exports = { queryGnm };
