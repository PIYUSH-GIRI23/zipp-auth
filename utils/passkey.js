import { redis, safeRedisOperation, inMemoryCache } from '../redis/redis_init.js';

const PASSKEY_PREFIX = 'passkey:';
const PASSKEY_EXPIRY = 120; // 2 minutes 

export async function storePasskey(userId, passkey) {
    return safeRedisOperation(
        async () => {
            const key = PASSKEY_PREFIX + userId;
            await redis.setex(key, PASSKEY_EXPIRY, passkey);
            return true;
        },
        () => {
            inMemoryCache.set(PASSKEY_PREFIX + userId, {
                passkey,
                expiry: Date.now() + (PASSKEY_EXPIRY * 1000)
            });
            return true;
        }
    );
}


export async function verifyPasskey(userId, passkey) {
    return safeRedisOperation(
        async () => {
            const key = PASSKEY_PREFIX + userId;
            const storedPasskey = await redis.get(key);
            
            if (storedPasskey === passkey) {
                await redis.del(key);
                return true;
            }
            return false;
        },
        () => {
            const key = PASSKEY_PREFIX + userId;
            const stored = inMemoryCache.get(key);
            
            if (stored && stored.passkey === passkey && stored.expiry > Date.now()) {
                inMemoryCache.delete(key);
                return true;
            }
            return false;
        }
    );
}