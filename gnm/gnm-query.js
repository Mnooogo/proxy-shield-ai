// /gnm/gnm-query.js
import { ChromaClient } from "chromadb";
import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { RetrievalQAChain } from "langchain/chains";
import { OpenAI } from "langchain/llms/openai";
import { Chroma } from "langchain/vectorstores/chroma";

const client = new ChromaClient();
const collectionName = "gnm-docs"; // Име на базата, вече качена

async function askGNM(question) {
  const vectorstore = await Chroma.fromExistingCollection(
    new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
    { collectionName, client }
  );

  const model = new OpenAI({ openAIApiKey: process.env.OPENAI_API_KEY, temperature: 0.3 });
  const chain = RetrievalQAChain.fromLLM(model, vectorstore.asRetriever());

  const res = await chain.call({ query: question });
  console.log("💬 Answer:", res.text);
}

askGNM("What does German New Medicine say about eczema?");
