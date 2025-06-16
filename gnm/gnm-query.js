// ✅ /gnm/gnm-query.js (final version with local ChromaDB)
const path = require("path");
const { Chroma } = require("@langchain/community/vectorstores/chroma");
const { OpenAIEmbeddings } = require("@langchain/openai");
const { RetrievalQAChain } = require("langchain/chains");
const { OpenAI } = require("@langchain/openai");

const queryGnm = async (question) => {
  const vectorStore = await Chroma.fromExistingIndex(
    new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
    { 
      collectionName: "gnm-docs",
      indexPath: path.join(__dirname, "db")
    }
  );

  const chain = RetrievalQAChain.fromLLM(
    new OpenAI({ openAIApiKey: process.env.OPENAI_API_KEY, temperature: 0.2 }),
    vectorStore.asRetriever()
  );

  const response = await chain.call({ query: question });
  return response.text;
};

module.exports = { queryGnm };

