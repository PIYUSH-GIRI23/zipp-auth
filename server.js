import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import manageAuth from './routes/manageAuth.js';
import { connectToDatabase } from './db/init.js';

dotenv.config();
const app = express();

const PORT = process.env.PORT || 5000;

connectToDatabase();

app.use(cors({
    origin: '*'
}));

app.use(express.json());

app.use('/', manageAuth);
app.get('/', (req, res) => {
    res.send('Auth service is running');
});
app.listen(PORT, () => {
    console.log(`auth is running on port ${PORT}`);
});