import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';

dotenv.config();

// Get salt rounds from environment variable or default to 12
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS);

export const hashPassword = async (password) => {
    try {
        if (!password) {
            throw new Error('Password is required for hashing');
        }
        
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        return hashedPassword;
    } 
    catch (error) {
        console.error('Error hashing password:', error);
        throw new Error('Failed to hash password');
    }
};


export const comparePassword = async (password, hashedPassword) => {
    try {
        if (!password || !hashedPassword) {
            throw new Error('Both password and hashed password are required for comparison');
        }
        
        const isMatch = await bcrypt.compare(password, hashedPassword);
        return isMatch;
    } catch (error) {
        console.error('Error comparing passwords:', error);
        throw new Error('Failed to compare passwords');
    }
};

export default {
    hashPassword,
    comparePassword
};