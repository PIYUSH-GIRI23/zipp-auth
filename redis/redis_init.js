import Redis from "ioredis";
import 'dotenv/config';
import {
    OTP_EXPIRY_SECONDS,
    MAX_OTP_ATTEMPTS,
    generateOTPData,
    validateStoredOTPData,
    getOtpKey,
    getAttemptKey,
    getDailyAttemptKey,
    getSecondsUntilNextReset,
    logOtpEvent
} from '../utils/otp.js';

// -------------------------
// Redis connection
// -------------------------
const redis = new Redis({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
    password: process.env.REDIS_PASSWORD || undefined,
    connectTimeout: 5000,          // 5 second connection timeout
    commandTimeout: 3000,          // 3 second command timeout
    retryDelayOnFailover: 100,     // Fast failover
    maxRetriesPerRequest: 1,       // Don't retry commands, fail fast
    lazyConnect: true,             // Don't connect immediately
    keepAlive: 30000,              // Keep connection alive
});

// -------------------------
// Event Queue Types
// -------------------------
const EVENT_TYPES = {
    SIGNUP: 'user:signup',
    LOGIN: 'user:login',
    PASSWORD_UPDATE: 'user:password:update',
    USERNAME_UPDATE: 'user:username:update',
    PIN_UPDATE: 'user:pin:update',
    ACCOUNT_DELETE: 'user:account:delete',
    OTP_GENERATED: 'user:otp:generated'
};

redis.on('connect', () => { 
    console.log("✅ Redis OTP service connected successfully");
    redisAvailable = true; 
});

redis.on('error', (err) => { 
    console.error("❌ Redis OTP connection error:", err.message);
    redisAvailable = false; 
});

redis.on('close', () => {
    console.log("🔌 Redis OTP connection closed");
    redisAvailable = false;
});

redis.on('reconnecting', () => {
    console.log("🔄 Redis OTP reconnecting...");
    redisAvailable = false;
});


const inMemoryCache = new Map();
let redisAvailable = true;

async function safeRedisOperation(operation, fallback) {
    if (!redisAvailable) {
        console.log("Redis unavailable, using fallback");
        return fallback ? fallback() : null;
    }
    
    try {
        const result = await Promise.race([
            operation(),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Redis operation timeout')), 2000)
            )
        ]);
        return result;
    } catch (error) {
        console.error("Redis error, using fallback:", error.message);
        redisAvailable = false;
        return fallback ? fallback() : null;
    }
}

async function pushEventToQueue(eventType, eventData) {
    if (!EVENT_TYPES[eventType]) {
        throw new Error('Invalid event type');
    }

    try {
        // Add timestamp and event type to the event data
        const event = {
            ...eventData,
            eventType: EVENT_TYPES[eventType],
            timestamp: Date.now()
        };

        await redis.publish(EVENT_TYPES[eventType], JSON.stringify(event));
        return true;
    } catch (error) {
        console.error('Failed to push event to queue:', error);
        return false;
    }
}

// -------------------------
// Event Push Functions
// -------------------------

export async function notifySignup(email, createdAt, name, deviceInfo = null) {
    console.log("Notify signup for:", email);
    return pushEventToQueue('SIGNUP', { 
        email,
        name,
        createdAt, // Unix timestamp of account creation
        createdAtISO: new Date(createdAt).toISOString(), // ISO string format for better readability
        deviceInfo // Device info (IP, location, OS, browser)
    });
}

export async function notifyLogin(email, loginAt, name, deviceInfo = null) {
    console.log(loginAt,new Date(loginAt).toISOString());
    return pushEventToQueue('LOGIN', { 
        email,
        name,
        loginAt, // Unix timestamp of login
        loginAtISO: new Date(loginAt).toISOString(),
        deviceInfo // Device info (IP, location, OS, browser)
    });
}

export async function notifyPasswordUpdate(email, updatedAt, name, deviceInfo = null) {
    return pushEventToQueue('PASSWORD_UPDATE', { 
        email,
        updatedAt,
        updatedAtISO: new Date(updatedAt).toISOString(),
        deviceInfo,
        name
    });
}

export async function notifyUsernameUpdate(email, updatedAtISO, oldUsername, newUsername, deviceInfo = null,name) {
    const timestamp = Date.now();
    return pushEventToQueue('USERNAME_UPDATE', { 
        email,
        oldUsername,
        newUsername,
        updatedAt: timestamp,
        updatedAtISO: new Date(timestamp).toISOString(),
        deviceInfo,
        name
    });
}

export async function notifyPinUpdate(email, updatedAtISO, name, deviceInfo = null) {
    const timestamp = Date.now();
    return pushEventToQueue('PIN_UPDATE', { 
        email,
        updatedAt: timestamp,
        updatedAtISO: new Date(timestamp).toISOString(),
        deviceInfo,
        name
    });
}

export async function notifyAccountDelete(email, deletedAtISO, deviceInfo = null, name) {
    const timestamp = Date.now();
    return pushEventToQueue('ACCOUNT_DELETE', { 
        email,
        deletedAt: timestamp,
        deletedAtISO: new Date(timestamp).toISOString(),
        deviceInfo,
        name
    });
}

// -------------------------
// OTP Service Functions
// -------------------------

export async function generateAndStoreOTP(userId) {
    if (!userId) {
        return { success: false, error: "User ID is required" };
    }

    try {
        // Generate OTP data
        const otpData = generateOTPData(userId);
        const otpKey = getOtpKey(userId);
        const attemptKey = getAttemptKey(userId);

        // Store OTP with expiry and reset attempt counter
        const stored = await safeRedisOperation(
            async () => {
                await redis.setex(otpKey, OTP_EXPIRY_SECONDS, JSON.stringify(otpData));
                await redis.del(attemptKey); // Reset current session attempts
                return true;
            },
            () => {
                // Fallback: Store in memory with auto-cleanup
                inMemoryCache.set(otpKey, otpData);
                inMemoryCache.delete(attemptKey);
                setTimeout(() => {
                    inMemoryCache.delete(otpKey);
                }, OTP_EXPIRY_SECONDS * 1000);
                return true;
            }
        );

        if (stored) {
            // Push OTP event to queue with email
            await pushEventToQueue('OTP_GENERATED', { 
                email: userId, // Using email instead of userId
                otp: otpData.otp,
                expirySeconds: OTP_EXPIRY_SECONDS,
                generatedAt: Date.now(),
                generatedAtISO: new Date().toISOString()
            });

            logOtpEvent("GENERATED", userId, `OTP generated, expires in ${OTP_EXPIRY_SECONDS}s`);
            return { success: true, otp: otpData.otp };
        } else {
            return { success: false, error: "Failed to store OTP" };
        }
    } catch (error) {
        logOtpEvent("ERROR", userId, `Generation failed: ${error.message}`);
        return { success: false, error: "Failed to generate OTP" };
    }
}

export async function verifyOTP(userId, inputOtp) {
    if (!userId || !inputOtp) {
        return { success: false, error: "User ID and OTP are required" };
    }

    const otpKey = getOtpKey(userId);
    const attemptKey = getAttemptKey(userId);

    try {
        // Get stored OTP data
        const storedData = await safeRedisOperation(
            () => redis.get(otpKey),
            () => inMemoryCache.get(otpKey)
        );

        // Validate OTP data
        const validationResult = validateStoredOTPData(storedData);
        if (!validationResult.isValid) {
            if (validationResult.error === "OTP has expired") {
                // Clean up expired OTP
                await safeRedisOperation(
                    () => redis.del(otpKey),
                    () => inMemoryCache.delete(otpKey)
                );
            }
            return { success: false, error: validationResult.error };
        }

        const otpData = validationResult.otpData;

        // Get current attempt count
        const currentAttempts = await safeRedisOperation(
            async () => {
                const attempts = await redis.get(attemptKey);
                return attempts ? parseInt(attempts) : 0;
            },
            () => {
                const attempts = inMemoryCache.get(attemptKey);
                return attempts || 0;
            }
        );

        // Check max attempts
        if (currentAttempts >= MAX_OTP_ATTEMPTS) {
            logOtpEvent("BLOCKED", userId, `Max attempts (${MAX_OTP_ATTEMPTS}) exceeded`);
            // Clean up OTP after max attempts
            await safeRedisOperation(
                async () => {
                    await redis.del(otpKey);
                    await redis.del(attemptKey);
                },
                () => {
                    inMemoryCache.delete(otpKey);
                    inMemoryCache.delete(attemptKey);
                }
            );
            return { success: false, error: "Maximum OTP attempts exceeded" };
        }

        // Verify OTP
        if (otpData.otp === inputOtp.toString()) {
            await safeRedisOperation(
                async () => {
                    await redis.del(otpKey);
                    await redis.del(attemptKey);
                },
                () => {
                    inMemoryCache.delete(otpKey);
                    inMemoryCache.delete(attemptKey);
                }
            );
            
            logOtpEvent("VERIFIED", userId, "OTP verified successfully");
            return { success: true };
        } else {
            // Wrong OTP - increment attempts
            const newAttempts = currentAttempts + 1;
            await safeRedisOperation(
                () => redis.setex(attemptKey, OTP_EXPIRY_SECONDS, newAttempts),
                () => {
                    inMemoryCache.set(attemptKey, newAttempts);
                    setTimeout(() => inMemoryCache.delete(attemptKey), OTP_EXPIRY_SECONDS * 1000);
                }
            );

            const remaining = MAX_OTP_ATTEMPTS - newAttempts;
            logOtpEvent("INVALID", userId, `Wrong OTP, ${remaining} attempts remaining`);
            
            return { 
                success: false, 
                error: "Invalid OTP", 
                attemptsRemaining: remaining 
            };
        }
    } catch (error) {
        logOtpEvent("ERROR", userId, `Verification failed: ${error.message}`);
        return { success: false, error: "Failed to verify OTP" };
    }
}

// Export Redis instance and utilities
export { redis, safeRedisOperation, inMemoryCache, EVENT_TYPES };