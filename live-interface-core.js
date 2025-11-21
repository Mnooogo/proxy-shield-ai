// live-interface-core.js
// Prototype: Pulse Analyzer for the Living Interface

function analyzeText(inputRaw) {
  const text = (inputRaw || '').toString().trim();

  if (!text) {
    return {
      rhythm: { pace: "neutral", density: "simple", length: 0 },
      emo: { intensity: "low", tone: "neutral" },
      concepts: []
    };
  }

  // --- 1) Rhythm extraction ---
  const words = text.split(/\s+/).length;
  const sentencesArr = text.split(/[.!?]/).filter(s => s.trim().length > 0);
  const sentences = sentencesArr.length;
  const avgSentence = sentences > 0 ? words / sentences : words;
  const punctuation = (text.match(/[,;:]/g) || []).length;

  const rhythm = {
    pace:
      avgSentence < 8 ? "fast" :
      avgSentence < 15 ? "medium" : "slow",
    density: punctuation > 2 ? "complex" : "simple",
    length: words
  };

  // --- 2) Emotional wave (prototype) ---
  const emo = {
    intensity:
      /!/.test(text) ? "high" :
      text.length < 40 ? "low" : "medium",

    tone:
      /(любов|красиво|вдъхновение|спокойно|ясно|радост|благодарност)/i.test(text) ? "positive" :
      /(трудно|болка|страх|тъга|гняв|объркан|хаос|загуба)/i.test(text) ? "negative" :
      "neutral"
  };

  // --- 3) Cognitive nodes (themes) ---
  const concepts = [];
  const themes = {
    consciousness: /(съзнание|дух|внимание|осъзнатост|поле)/i,
    structure: /(форма|памет|вода|решетка|структура)/i,
    identity: /(аз|себе|личност|его)/i,
    flow: /(движение|ритъм|вълна|пулс|поток)/i
  };

  for (const key in themes) {
    if (themes[key].test(text)) {
      concepts.push(key);
    }
  }

  return {
    rhythm,
    emo,
    concepts
  };
}

module.exports = { analyzeText };
