import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

let db;
let client;

const connectToDatabase = async () => {
  try {
    const uri = process.env.MONGO_URI;
    
    client = new MongoClient(uri);

    await client.connect();
    console.log('Connected to MongoDB successfully');

    db = client.db();
  
    await createAuthCollection();
    
    return db;
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
};

const createAuthCollection = async () => {
  try {
    const collections = await db.listCollections({ name: 'auth' }).toArray();
    
    if (collections.length === 0) {
      await db.createCollection('auth');
      console.log('Auth collection created successfully');
    }

    await createIndexes();
  } catch (error) {
    console.error('Error creating auth collection:', error);
    throw error;
  }
};

const createIndexes = async () => {
  try {
    const authCollection = db.collection('auth');
    
    await authCollection.createIndex(
      { email: 1 }, 
      { unique: true, name: 'email_unique_index' }
    );

    await authCollection.createIndex(
      { username: 1 }, 
      { unique: true, name: 'username_unique_index' }
    );
    
    console.log('Indexes created successfully for auth collection');
  } catch (error) {
    console.error('Error creating indexes:', error);
    throw error;
  }
};

const getDatabase = () => {
  if (!db) {
    throw new Error('Database not initialized. Call connectToDatabase first.');
  }
  return db;
};

const getAuthCollection = () => {
  if (!db) {
    throw new Error('Database not initialized. Call connectToDatabase first.');
  }
  return db.collection('auth');
};

const getClipCollection = () => {
  if (!db) {
    throw new Error('Database not initialized. Call connectToDatabase first.');
  }
  return db.collection('clip');
};

const closeConnection = async () => {
  if (client) {
    await client.close();
    console.log('MongoDB connection closed');
  }
};

process.on('SIGINT', async () => {
  await closeConnection();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await closeConnection();
  process.exit(0);
});

export {
  connectToDatabase,
  getDatabase,
  getAuthCollection,
  getClipCollection,
  closeConnection
};
