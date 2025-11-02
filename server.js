import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import manageAuth from './routes/manageAuth.js';
import { connectToDatabase } from './db/init.js';

dotenv.config();
const app = express();

const PORT = process.env.PORT || 5000;

async function startServer() {
    try {
        await connectToDatabase();
        
        app.use(cors({
            origin: '*'
        }));
        
        app.get('/', (req, res) => {
            res.send('Auth service is running');
        });
        app.use(express.json());
        
        app.use('/', manageAuth);
        
        app.listen(PORT, () => {
            console.log(`auth is running on port ${PORT}`);
        });

    }
    catch (error) {
        console.error('❌ Server startup error:', error);
        process.exit(1);
    }
}

startServer();