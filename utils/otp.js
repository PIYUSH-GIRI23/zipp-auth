import 'dotenv/config';

const OTP_EXPIRY_SECONDS = parseInt(process.env.OTP_EXPIRY_SECONDS) || 120; // 2 minutes default
const OTP_LENGTH = parseInt(process.env.OTP_LENGTH) || 6;
const MAX_OTP_ATTEMPTS = parseInt(process.env.MAX_OTP_ATTEMPTS) || 3;
const ATTEMPT_RESET_HOURS = parseInt(process.env.ATTEMPT_RESET_HOURS) || 24; // Reset attempts after 24 hours

function generateOTP() {
    const min = Math.pow(10, OTP_LENGTH - 1);
    const max = Math.pow(10, OTP_LENGTH) - 1;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getOtpKey(emailid) {
    return `otp:${emailid}`;
}

function getAttemptKey(emailid) {
    return `otp_attempts:${emailid}`;
}

function getDailyAttemptKey(emailid) {
    const resetInterval = ATTEMPT_RESET_HOURS;
    const now = new Date();
    const resetPeriod = Math.floor(now.getTime() / (resetInterval * 60 * 60 * 1000));
    return `otp_period_attempts:${emailid}:${resetPeriod}`;
}

function getSecondsUntilNextReset() {
    const now = new Date();
    const resetIntervalMs = ATTEMPT_RESET_HOURS * 60 * 60 * 1000; // Convert hours to milliseconds
    const currentPeriod = Math.floor(now.getTime() / resetIntervalMs);
    const nextResetTime = (currentPeriod + 1) * resetIntervalMs;
    return Math.floor((nextResetTime - now.getTime()) / 1000);
}

function logOtpEvent(type, emailid, info = "") {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [OTP_${type}] User: ${emailid} ${info}`);
}

export function generateOTPData(emailid) {
    if (!emailid) {
        throw new Error("Email ID is required");
    }

    const otp = generateOTP();
    return {
        otp: otp.toString(),
        createdAt: Date.now(),
        attempts: 0
    };
}

export function validateStoredOTPData(storedData, expirySeconds = OTP_EXPIRY_SECONDS) {
    if (!storedData) {
        return { isValid: false, error: "OTP has expired or does not exist" };
    }

    const otpData = typeof storedData === 'string' ? JSON.parse(storedData) : storedData;
    
    const now = Date.now();
    const age = (now - otpData.createdAt) / 1000;
    if (age > expirySeconds) {
        return { isValid: false, error: "OTP has expired" };
    }

    return { isValid: true, otpData };
}

export {
    OTP_EXPIRY_SECONDS,
    OTP_LENGTH,
    MAX_OTP_ATTEMPTS,
    ATTEMPT_RESET_HOURS,
    getOtpKey,
    getAttemptKey,
    getDailyAttemptKey,
    getSecondsUntilNextReset,
    logOtpEvent
};
