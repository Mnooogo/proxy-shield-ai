// ✅ gnm/gnm-loader.js – само за първоначално генериране на db
const path = require("path");
const fs = require("fs");
const { OpenAIEmbeddings } = require("@langchain/openai");
const { Chroma } = require("@langchain/community/vectorstores/chroma");
const { RecursiveCharacterTextSplitter } = require("langchain/text_splitter");
const { Document } = require("langchain/document");

// ✅ Зареждаме JSON fallback (може и от PDF)
const gnmJson = JSON.parse(fs.readFileSync(path.join(__dirname, "gnm-knowledge.json"), "utf8"));

// 🔍 Превръщаме в документи
const docs = gnmJson.map(entry => new Document({ pageContent: `${entry.question}\n${entry.answer}` }));

// ✅ Разбиване на фрагменти (ако искаш по-фин контрол)
const splitter = new RecursiveCharacterTextSplitter({ chunkSize: 300, chunkOverlap: 30 });

async function run() {
  const splitDocs = await splitter.splitDocuments(docs);
  const embeddings = new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY });

  await Chroma.fromDocuments(splitDocs, embeddings, {
    collectionName: "gnm-docs",
    indexPath: path.join(__dirname, "db")  // 👉 записва тук
  });

  console.log("✅ GNM index created at /gnm/db");
}

run();
