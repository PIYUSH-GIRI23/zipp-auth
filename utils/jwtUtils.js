import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { getAuthCollection } from '../db/init.js';
import { ObjectId } from 'mongodb';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is required in environment variables');
}

// Token expiration durations
const SHORT_TERM_EXPIRY = '7d';   // Normal login
const LONG_TERM_EXPIRY = '30d';   // Remember me
const REFRESH_TOKEN_EXPIRY = '90d'; // Refresh token validity

/**
 * Generate JWT and refresh token
 */
export const generateTokens = (payload, rememberMe = false) => {
    try {
        if (!payload || !payload.userId) throw new Error('Payload with userId required for token generation');

        const jwtExpiry = rememberMe ? LONG_TERM_EXPIRY : SHORT_TERM_EXPIRY;

        const jwtToken = jwt.sign(
            { userId: payload.userId, type: 'access' },
            JWT_SECRET,
            {
                expiresIn: jwtExpiry,
                issuer: 'zipp-auth',
                audience: 'zipp-users'
            }
        );

        const refreshToken = jwt.sign(
            { userId: payload.userId, type: 'refresh' },
            JWT_SECRET,
            {
                expiresIn: REFRESH_TOKEN_EXPIRY,
                issuer: 'zipp-auth',
                audience: 'zipp-users'
            }
        );

        return {
            accessToken: jwtToken,
            refreshToken,
            expiresIn: rememberMe ? '30 days' : '7 days'
        };
    } 
    catch (error) {

        throw new Error('Failed to generate authentication tokens');
    }
};

export const verifyToken = async (token, deviceInfo) => {
    try {
        if (!token) throw new Error('Token is required for verification');

        const decoded = jwt.verify(token, JWT_SECRET, {
            issuer: 'zipp-auth',
            audience: 'zipp-users'
        });

        if (!deviceInfo || !deviceInfo.ip) throw new Error('Device information missing');

        const authCollection = getAuthCollection();
        const user = await authCollection.findOne({ _id: new ObjectId(decoded.userId) });
        if (!user) throw new Error('User not found');

        const history = user.history || [];
        const currentIp = deviceInfo.ip;
        const ipEntry = history.find(h => h.ip === currentIp);

        if (!ipEntry) {
            throw new Error('Unknown device or session expired');
        }

        // Update last login timestamp (use atomic update to avoid overwriting history)
        const currentTime = Date.now();
        ipEntry.data[ipEntry.data.length - 1] = currentTime;

        // Update only the matching history entry's data and lastUpdated atomically
        await authCollection.updateOne(
            { _id: user._id, 'history.ip': currentIp },
            { $set: { 'history.$.data': ipEntry.data, lastUpdated: currentTime } }
        );

        return {
            valid: true,
            decoded,
            expired: false
        };
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return {
                valid: false,
                decoded: null,
                expired: true,
                error: 'Token expired'
            };
        } else if (error.name === 'JsonWebTokenError') {
            return {
                valid: false,
                decoded: null,
                expired: false,
                error: 'Invalid token'
            };
        } else {
            return {
                valid: false,
                decoded: null,
                expired: false,
                error: error.message
            };
        }
    }
};


export const renewJWT = async (refreshToken, deviceInfo, rememberMe = false) => {
    try {
        if (!refreshToken) throw new Error('Refresh token is required');
        if (!deviceInfo || !deviceInfo.ip) throw new Error('Device information is required for token renewal');

        const decoded = jwt.decode(refreshToken);
        if (!decoded || !decoded.userId) throw new Error('Invalid refresh token format');

        const verification = await verifyToken(refreshToken, deviceInfo);
        if (!verification.valid) {
            const authCollection = getAuthCollection();
            await authCollection.updateOne(
                { _id: new ObjectId(decoded.userId) },
                { $pull: { history: { ip: deviceInfo.ip } } }
            );
            throw new Error(verification.error || 'Invalid or expired refresh token');
        }

        if (verification.decoded.type !== 'refresh') {
            throw new Error('Invalid token type - refresh token required');
        }

        const payload = { userId: verification.decoded.userId };
        return generateTokens(payload, rememberMe);
    }
     catch (error) {
        throw new Error(`Failed to renew JWT token: ${error.message}`);
    }
};

export const renewRefreshToken = async (refreshToken, deviceInfo) => {
    try {
        if (!refreshToken) throw new Error('Refresh token is required');
        if (!deviceInfo || !deviceInfo.ip) throw new Error('Device information is required for token renewal');

        const verification = await verifyToken(refreshToken, deviceInfo);

        if (!verification.valid) throw new Error(verification.error || 'Invalid or expired refresh token');
        if (verification.decoded.type !== 'refresh')
            throw new Error('Invalid token type - refresh token required');

        const newRefreshToken = jwt.sign(
            { userId: verification.decoded.userId, type: 'refresh' },
            JWT_SECRET,
            {
                expiresIn: REFRESH_TOKEN_EXPIRY,
                issuer: 'zipp-auth',
                audience: 'zipp-users'
            }
        );

        return {
            refreshToken: newRefreshToken,
            expiresIn: '90 days'
        };
    } catch (error) {
        
        throw new Error(`Failed to renew refresh token: ${error.message}`);
    }
};

export const extractTokenFromHeader = (authHeader) => {
    if (!authHeader) return null;
    return authHeader.startsWith('Bearer ') ? authHeader.substring(7) : authHeader;
};


export const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
        return res.status(401).json({
            error: 'Access token required',
            code: 'TOKEN_MISSING'
        });
    }

    const deviceInfo = req.body.deviceInfo || req.query.deviceInfo;

    try {
        const verification = await verifyToken(token, deviceInfo);

        if (!verification.valid) {
            return res.status(verification.expired ? 401 : 403).json({
                error: verification.expired ? 'Token expired' : 'Invalid token',
                code: verification.expired ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID'
            });
        }

        req.user = verification.decoded;
        next();
    } 
    catch (error) {

        if (error.message.includes('Unknown device') || error.message.includes('Device information missing')) {
            return res.status(403).json({
                error: error.message,
                code: 'DEVICE_UNAUTHORIZED'
            });
        }

        return res.status(401).json({
            error: error.message || 'Authentication error',
            code: 'AUTH_ERROR'
        });
    }
};


export const decodeToken = (token) => {
    try {
        return jwt.decode(token);
    } 
    catch (error) {

        return null;
    }
};

export default {
    generateTokens,
    verifyToken,
    renewJWT,
    renewRefreshToken,
    extractTokenFromHeader,
    authenticateToken,
    decodeToken
};
