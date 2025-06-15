// ✅ /gnm/gnm-query.js – FINAL VERSION (CommonJS + exportable)
const { ChromaClient } = require("chromadb");
const { OpenAIEmbeddings } = require("langchain/embeddings/openai");
const { RetrievalQAChain } = require("langchain/chains");
const { OpenAI } = require("langchain/llms/openai");
const { Chroma } = require("langchain/vectorstores/chroma");

const client = new ChromaClient();
const collectionName = "gnm-docs"; // Име на базата с GNM PDF-а

const queryGnm = async (question) => {
  const vectorstore = await Chroma.fromExistingCollection(
    new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
    { collectionName, client }
  );

  const model = new OpenAI({ openAIApiKey: process.env.OPENAI_API_KEY, temperature: 0.3 });
  const chain = RetrievalQAChain.fromLLM(model, vectorstore.asRetriever());

  const res = await chain.call({ query: question });
  return res.text;
};

module.exports = { queryGnm };
