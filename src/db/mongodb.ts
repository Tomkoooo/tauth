// src/db/mongodb.ts
import { MongoClient, Db } from 'mongodb';

let client: MongoClient | null = null;

export const connectToDatabase = async (): Promise<Db> => {
  const mongoUri = process.env.MONGO_URI;
  const dbName = process.env.MONGO_DB_NAME;

  if (!mongoUri) {
    throw new Error("MONGO_URI env variable is missing.");
  }

  if (!dbName) {
    throw new Error("MONGO_DB_NAME env variable is missing.");
  }

  if (!client) {
    client = new MongoClient(mongoUri);
    await client.connect();
  }

  return client.db(dbName);
};
