import { generateTokens , authenticateToken, renewJWT, renewRefreshToken, verifyToken} from '../utils/jwtUtils.js';

export const jwt = async(req,res,next)=>{
    try{
        const token = JSON.parse(req.headers['token']);
        const deviceInfo = req.body.deviceInfo || {};

        if(!token){
            return res.status(401).json({ message: 'Unauthorized - No token provided' });
        }
        let verification = await verifyToken(token.access_token , deviceInfo);

        if (!verification.valid && verification.expired) {
            try {
                const newTokens = await renewJWT(token.refresh_token , deviceInfo);
                res.set('New-Access-Token', newTokens.accessToken);
                res.set('New-Refresh-Token', newTokens.refreshToken);
                verification = await verifyToken(newTokens.accessToken , deviceInfo);
            }
            catch (error) {
                return res.status(401).json({
                    error: 'Session expired. Please sign in again.',
                    code: 'SESSION_EXPIRED'
                });
            }
        } 
        else if (!verification.valid) {
            return res.status(403).json({
                error: 'Invalid token',
                code: 'TOKEN_INVALID'
            });
        }

        req.userId = verification.decoded.userId;
      
        
        next();
    }
    catch(err){
        return res.status(500).json({ message: 'Internal Server Error' });
    }
}