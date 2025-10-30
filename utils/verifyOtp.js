import { 
    generateOTPData,
    validateStoredOTPData,
    OTP_EXPIRY_SECONDS,
    MAX_OTP_ATTEMPTS,
    getOtpKey,
    getAttemptKey,
    logOtpEvent
} from './otp.js';

import { redis } from '../redis/redis_init.js';


const inMemoryCache = new Map();
let redisAvailable = true;

async function safeRedisOperation(operation, fallback) {
    if (!redisAvailable) {
        console.log("Redis unavailable, using fallback for OTP");
        return fallback ? fallback() : null;
    }
    
    try {
        const result = await Promise.race([
            operation(),
            new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Redis OTP operation timeout')), 2000)
            )
        ]);
        return result;
    } 
    catch (error) {
        console.error("Redis OTP error, using fallback:", error.message);
        redisAvailable = false;
        return fallback ? fallback() : null;
    }
}

export async function generateOtpAndPush(email , deviceInfo) {
    if (!email) {
        return { success: false, message: "Email is required" };
    }
    
    try {
        // Generate OTP data
        const otpData = generateOTPData(email);
        const otpKey = getOtpKey(email);
        const attemptKey = getAttemptKey(email);
        
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
            // Push event to queue via redis_init.js
            // Use the existing push mechanism
            await redis.publish('user:otp:generated', JSON.stringify({
                email: email,
                otp: otpData.otp,
                expirySeconds: OTP_EXPIRY_SECONDS,
                expiryMinutes: Math.ceil(OTP_EXPIRY_SECONDS / 60),
                generatedAt: Date.now(),
                generatedAtISO: new Date().toISOString(),
                deviceInfo: deviceInfo
            }));
            
            logOtpEvent("GENERATED", email, `OTP generated for verification`);

            return { 
                success: true, 
                message: "OTP generated and notification sent",
                otp: otpData.otp, 
                expirySeconds: OTP_EXPIRY_SECONDS
            };
        } else {
            return { success: false, message: "Failed to store OTP" };
        }
    } catch (error) {
        console.error("OTP generation error:", error);
        logOtpEvent("ERROR", email, `Generation failed: ${error.message}`);
        return { success: false, message: "Failed to generate OTP" };
    }
}


export async function verifyUserOtp(email, inputOtp) {
    if (!email || !inputOtp) {
        return { success: false, message: "Email and OTP are required" };
    }
    
    const otpKey = getOtpKey(email);
    const attemptKey = getAttemptKey(email);
    
    try {

        const storedData = await safeRedisOperation(
            () => redis.get(otpKey),
            () => inMemoryCache.get(otpKey)
        );
        
        const validationResult = validateStoredOTPData(storedData);
        if (!validationResult.isValid) {
            if (validationResult.error === "OTP has expired") {

                await safeRedisOperation(
                    () => redis.del(otpKey),
                    () => inMemoryCache.delete(otpKey)
                );
            }
            return { success: false, message: validationResult.error };
        }
        
        const otpData = validationResult.otpData;
      
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
        
        // Check if max attempts exceeded
        if (currentAttempts >= MAX_OTP_ATTEMPTS) {
            logOtpEvent("BLOCKED", email, `Max attempts (${MAX_OTP_ATTEMPTS}) exceeded`);
            
            // Clean up OTP data after max attempts
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
            
            return { 
                success: false, 
                message: `Maximum attempts exceeded. Please request a new OTP.`,
                attemptsRemaining: 0
            };
        }
        
        // Compare provided OTP with stored OTP
        if (otpData.otp === inputOtp.toString()) {
            // OTP verified - clean up
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
            
            logOtpEvent("VERIFIED", email, "OTP verified successfully");
            return { success: true, message: "OTP verified successfully" };
        } 
        else {
            // Wrong OTP - increment attempts
            const newAttempts = currentAttempts + 1;
            await safeRedisOperation(
                () => redis.setex(attemptKey, OTP_EXPIRY_SECONDS, newAttempts),
                () => {
                    inMemoryCache.set(attemptKey, newAttempts);
                    setTimeout(() => inMemoryCache.delete(attemptKey), OTP_EXPIRY_SECONDS * 1000);
                }
            );
            
            const attemptsRemaining = MAX_OTP_ATTEMPTS - newAttempts;
            logOtpEvent("INVALID", email, `Wrong OTP, ${attemptsRemaining} attempts remaining`);
            
            return {
                success: false,
                message: `Invalid OTP. ${attemptsRemaining} attempts remaining.`,
                attemptsRemaining
            };
        }
    } 
    catch (error) {
        console.error("OTP verification error:", error);
        logOtpEvent("ERROR", email, `Verification failed: ${error.message}`);
        return { success: false, message: "Failed to verify OTP" };
    }
}

export default {
    generateOtpAndPush,
    verifyUserOtp
};
