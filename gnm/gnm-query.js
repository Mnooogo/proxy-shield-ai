const fs = require('fs');
const pdfParse = require('pdf-parse');

let gnmChunks = [];

async function loadGNM() {
  const dataBuffer = fs.readFileSync('./gnm/gnm.pdf');
  const pdfData = await pdfParse(dataBuffer);

  gnmChunks = pdfData.text
    .split(/\n\s*\n/) // split by empty lines (paragraphs)
    .map(p => p.trim())
    .filter(p => p.length > 100); // skip short junk

  console.log(`✅ Loaded ${gnmChunks.length} chunks from GNM PDF`);
}

async function queryGnm(query) {
  if (gnmChunks.length === 0) await loadGNM();

  const q = query.toLowerCase();
  const matches = gnmChunks.filter(p => p.toLowerCase().includes(q));

  if (matches.length === 0) return `❌ No relevant information found for: "${query}"`;

  return matches.slice(0, 3).join('\n\n'); // first 3 matches
}

module.exports = { queryGnm };
