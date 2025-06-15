// gnm/gnm-query.js

import { OpenAIEmbeddings } from "langchain/embeddings/openai";
import { RetrievalQAChain } from "langchain/chains";
import { OpenAI } from "langchain/llms/openai";
import { Chroma } from "langchain/vectorstores/chroma";
import { ChromaClient } from "langchain/vectorstores/chroma";
import * as dotenv from "dotenv";
dotenv.config();

const client = new ChromaClient();
const collectionName = "gnm-docs"; // името на векторната база, вече създадена

export async function queryGnm(question) {
  const vectorStore = await Chroma.fromExistingCollection(
    new OpenAIEmbeddings({ openAIApiKey: process.env.OPENAI_API_KEY }),
    { collectionName, client }
  );

  const model = new OpenAI({
    openAIApiKey: process.env.OPENAI_API_KEY,
    temperature: 0,
  });

  const chain = RetrievalQAChain.fromLLM(model, vectorStore.asRetriever());

  const response = await chain.call({ query: question });
  return response.text;
}
