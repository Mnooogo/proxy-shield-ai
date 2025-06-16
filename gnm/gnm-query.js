// /gnm/gnm-query.js

const path = require("path");
const { PDFLoader } = require("langchain/document_loaders/fs/pdf");
const { OpenAIEmbeddings, OpenAI } = require("@langchain/openai");
const { Chroma } = require("@langchain/community/vectorstores/chroma");
const { RetrievalQAChain } = require("langchain/chains");

const queryGnm = async (question) => {
  const loader = new PDFLoader(path.join(__dirname, "System prompt German new medicine.pdf"));
  const docs = await loader.load();

  const vectorStore = await Chroma.fromDocuments(docs, new OpenAIEmbeddings({
    openAIApiKey: process.env.OPENAI_API_KEY
  }));

  const chain = RetrievalQAChain.fromLLM(
    new OpenAI({ openAIApiKey: process.env.OPENAI_API_KEY, temperature: 0 }),
    vectorStore.asRetriever()
  );

  const response = await chain.call({ query: question });
  return response.text;
};

module.exports = { queryGnm };
