import * as fs from "fs";
import * as path from "path";
import { PDFLoader } from "langchain/document_loaders/fs/pdf";
import { OpenAIEmbeddings } from "@langchain/openai";
import { Chroma } from "@langchain/community/vectorstores/chroma";
import { RecursiveCharacterTextSplitter } from "langchain/text_splitter";
import { ChromaClient } from "chromadb";
import "dotenv/config";

const run = async () => {
  const pdfPath = path.join("gnm", "System prompt German new medicine.pdf");
  const loader = new PDFLoader(pdfPath);
  const rawDocs = await loader.load();

  const splitter = new RecursiveCharacterTextSplitter({
    chunkSize: 300,
    chunkOverlap: 50,
  });

  const docs = await splitter.splitDocuments(rawDocs);
  console.log(`📄 Loaded ${docs.length} chunks from GNM PDF.`);

  const chroma = new ChromaClient({ url: process.env.CHROMA_URL || "http://localhost:8000" });

  const vectorStore = await Chroma.fromDocuments(
    docs,
    new OpenAIEmbeddings({
      openAIApiKey: process.env.OPENAI_API_KEY,
    }),
    {
      collectionName: "gnm-docs",
      collectionMetadata: { description: "GNM insights and explanations" },
      persistDirectory: path.join("gnm", "db"),
      client: chroma
    }
  );

  console.log("✅ Chroma vector store created and persisted in /gnm/db");
};

run().catch(err => console.error("❌ GNM Loader Error:", err));
