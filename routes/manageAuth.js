import express from 'express';
import VerifyPassword from '../utils/dataVerification.js';
import { getAuthCollection , getClipCollection } from '../db/init.js';
import { generateUniqueUsername , validateUsernameFormat } from '../utils/usernameGenerator.js';
import { hashPassword , comparePassword} from '../utils/passwordHashing.js';
import { 
    generateTokens , 
    authenticateToken, 
    renewJWT, 
    renewRefreshToken, 
    verifyToken
} from '../utils/jwtUtils.js';
import {
     notifyLogin,
    notifySignup, 
    notifyPasswordUpdate, 
    notifyUsernameUpdate, 
    notifyPinUpdate, 
    notifyAccountDelete 
} from '../redis/redis_init.js';
import { ObjectId } from 'mongodb';
import { jwt } from '../middleware/jwt.js';
import passport from 'passport';
import { setupGoogleAuth } from '../utils/googleAuth.js';
import {deleteMultipleFiles} from '../utils/cloudinary/deleteFile.js';

const router=express.Router();

setupGoogleAuth();


router.get('/google', (req, res, next) => {
    try {
        const deviceInfo = req.query.deviceInfo ? JSON.parse(req.query.deviceInfo) : {};
        const state = encodeURIComponent(JSON.stringify(deviceInfo));

        passport.authenticate('google', {
            scope: ['profile', 'email'],
            prompt: 'consent',
            state 
        })(req, res, next);
    } catch (err) {
        console.error('Google OAuth init error:', err);
        res.status(400).json({ message: 'Invalid device info format' });
    }
});

router.get('/google/callback', passport.authenticate('google', { session: false }), async (req, res) => {
    try {
        if (!req.user || !req.user.user) {
            return res.status(401).json({ message: 'Authentication failed' });
        }

        const { user, isNewUser } = req.user;

    
        const deviceInfo = req.query.state ? JSON.parse(decodeURIComponent(req.query.state)) : {};

        const tokens = generateTokens({ userId: user._id.toString() }, true);

        if (isNewUser) {
            await notifySignup(user.email, user.dateOfJoining, user.name, deviceInfo)
                .catch(err => console.error('Redis notification error:', err));
        } else {
            await notifyLogin(user.email, user.lastLogin, user.name, deviceInfo)
                .catch(err => console.error('Redis notification error:', err));
        }

        const returnPath = req.query.returnTo || '/login';
        const clientUrl = new URL(`${process.env.CLIENT_URL}${returnPath}`);
        clientUrl.searchParams.append('accessToken', tokens.accessToken);
        clientUrl.searchParams.append('refreshToken', tokens.refreshToken);
        clientUrl.searchParams.append('expiresIn', tokens.expiresIn.toString());
        clientUrl.searchParams.append('isMailVerified', user.isMailVerified.toString());
        clientUrl.searchParams.append('isNewUser', isNewUser.toString());

        res.redirect(clientUrl.toString());

    } 
    catch (err) {
        console.error('Google callback error:', err);
        res.redirect(`${process.env.CLIENT_URL}/error?message=Authentication failed`);
    }
});

router.post('/signup', async (req, res) => {
    try {
        const data = req.body;
        const { firstName, lastName, email, password, rememberMe, deviceInfo } = data;

        if (!firstName || !email || !password) {
            return res.status(400).json({ message: 'Corrupted data provided' });
        }

        const passwordValid = await VerifyPassword(password);
        if (!passwordValid) {
            return res.status(400).json({ message: 'Password does not meet criteria' });
        }

        const authCollection = getAuthCollection();
        const existingUser = await authCollection.findOne({ email: email.trim() });
        if (existingUser) {
            return res.status(400).json({ message: 'Email is already in use' });
        }

        const username = await generateUniqueUsername(authCollection, firstName, lastName);
        const hashedPassword = await hashPassword(password);
        const currentTime = Date.now();

        const historyData = [];
        if (deviceInfo && deviceInfo.ip) {
            historyData.push({
                ip: deviceInfo.ip,
                data: [
                    deviceInfo.location?.country || '',
                    deviceInfo.browser?.name || '',
                    deviceInfo.browser?.version || '',
                    deviceInfo.os?.name || '',
                    deviceInfo.os?.version || '',
                    deviceInfo.device?.type || '',
                    deviceInfo.userAgent || '',
                    currentTime
                ]
            });
        }

        const userData = {
            firstName: firstName.trim(),
            lastName: lastName ? lastName.trim() : '',
            name: `${firstName.trim()} ${lastName ? lastName.trim() : ''}`.trim(),
            email: email.trim(),
            password: hashedPassword,
            username,
            dateOfJoining: currentTime,
            lastUpdated: currentTime,
            lastLogin: currentTime,
            pin: '',
            isMailVerified: false,
            usesPin: false,
            profile: '',
            accountPlan: 1,
            history: historyData,
            SignupType: 'manual'
        };

        const result = await authCollection.insertOne(userData);
        if (!result.insertedId) {
            return res.status(500).json({ message: 'Failed to insert user into database' });
        }

        const tokens = generateTokens({ userId: result.insertedId.toString() }, rememberMe);
        notifySignup(userData.email, userData.dateOfJoining, userData.name, deviceInfo)
            .catch(err => console.error('Redis notification error:', err));

        return res.status(201).json({
            message: 'User registered successfully',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresIn: tokens.expiresIn
        });

    } catch (err) {
        console.error('Signup Error:', err);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { email, username, password, pin, rememberMe, deviceInfo } = req.body;
        if (!email && !username) {
            return res.status(400).json({ message: 'Email or username is required' });
        }
        if (password && pin) {
            return res.status(400).json({ message: 'Provide either password or pin, not both' });
        }

        const authCollection = getAuthCollection();
        const user = email
            ? await authCollection.findOne({ email: email.trim() })
            : await authCollection.findOne({ username: username.trim() });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

            if(!user.password){
                return res.status(469).json({ message: 'Setup Password for Password Login' });
            }

        if (password) {
            const isPasswordValid = await comparePassword(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }
        }

        if (pin) {
            if (!user.isMailVerified) {
                return res.status(403).json({ message: 'Email not verified. Cannot use pin for login.' });
            }
            const userpin = await comparePassword(pin, user.pin);
            if (!userpin) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }
        }

        const tokens = generateTokens({ userId: user._id.toString() }, rememberMe);
        const currentTime = Date.now();

        // Use atomic updates to avoid overwriting the whole history array (prevents race conditions)
        if (deviceInfo && deviceInfo.ip) {
            const newEntry = {
                ip: deviceInfo.ip,
                data: [
                    deviceInfo.location?.country || '',
                    deviceInfo.browser?.name || '',
                    deviceInfo.browser?.version || '',
                    deviceInfo.os?.name || '',
                    deviceInfo.os?.version || '',
                    deviceInfo.device?.type || '',
                    deviceInfo.userAgent || '',
                    currentTime
                ]
            };

            // Try to update existing entry matching the IP atomically
            const updateExisting = await authCollection.updateOne(
                { _id: user._id, 'history.ip': deviceInfo.ip },
                { $set: { 'history.$.data': newEntry.data, lastLogin: currentTime, lastUpdated: currentTime } }
            );

            // If there was no existing entry for this IP, push a new one. Keep history capped to last 10 entries.
            if (updateExisting.matchedCount === 0) {
                await authCollection.updateOne(
                    { _id: user._id },
                    {
                        $push: { history: { $each: [newEntry], $slice: -10 } },
                        $set: { lastLogin: currentTime, lastUpdated: currentTime }
                    }
                );
            }
        } else {
            // No device info provided - only update login timestamps
            await authCollection.updateOne(
                { _id: user._id },
                { $set: { lastLogin: currentTime, lastUpdated: currentTime } }
            );
        }

        notifyLogin(user.email, currentTime, user.name, deviceInfo)
            .catch(err => console.error('Redis notification error:', err));

        res.status(200).json({
            message: 'Login successful',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresIn: tokens.expiresIn,
            isMailVerified: user.isMailVerified
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.post('/check-email', async (req, res) => {
    try{
        const { email } = req.body;
        if(!email){
            return res.status(400).json({ message: 'Email is required' });
        }

        const authCollection = getAuthCollection();
        const existingUser = await authCollection.findOne({ email: email.trim() });
        if (existingUser) {
            return res.status(200).json({ isUnique: false, message: 'Email is already in use' });
        } else {
            return res.status(200).json({ isUnique: true, message: 'Email is available' });
        }
    }
    catch(error){
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.post('/does-exists', async (req, res) => {
    try{
        const { email } = req.body;
        if(!email){
            return res.status(400).json({ message: 'Email is required' });
        }
        
        const authCollection = getAuthCollection();
        const existingUser = await authCollection.findOne({ email: email.trim() }); 
        if (existingUser) {
            return res.status(200).json({ isUnique: false, isMailVerified: existingUser.isMailVerified, message: 'User exists', usesPin: existingUser.usesPin });
        } else {
            return res.status(200).json({ isUnique: true, message: 'User does not exist' });
        }
    }
    catch(error){
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.post('/send-verification', jwt , async (req, res) => {
    try {
        const { deviceInfo } = req.body;
        const userId = req.userId;

        if (!userId) {
            return res.status(400).json({
                error: 'Invalid user ID in token',
                code: 'INVALID_USER_ID'
            });
        }

        const authCollection = getAuthCollection();

        const user = await authCollection.findOne({ _id:  new ObjectId(userId) });
        if(!user){
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const email = user ? user.email : null;

        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }
    
        
        if (user.isMailVerified) {
            return res.status(400).json({
                success: false,
                message: 'Email is already verified'
            });
        }
        
        const { generateOtpAndPush } = await import('../utils/verifyOtp.js');
    
        const otpResult = await generateOtpAndPush(user.email, deviceInfo);
        
        if (otpResult.success) {
            return res.status(200).json({
                success: true,
                message: 'Verification OTP sent to your email',
                expirySeconds: otpResult.expirySeconds,
            });
        } 
        else {
            return res.status(500).json({
                success: false,
                message: 'Failed to generate OTP'
            });
        }
    } 
    catch (error) {
        console.error('Send verification error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

router.post('/set-pin', jwt , async (req, res) => {
    try{
        const { deviceInfo , pin, password} = req.body;
        
        if(!pin){
            return res.status(400).json({ error: 'PIN is required' });
        }
        if(!password){
            return res.status(400).json({ error: 'Password is required' });
        }
        
        const  userId  = req.userId;
        

        if (!userId) {
            return res.status(400).json({
                error: 'Invalid user ID in token',
                code: 'INVALID_USER_ID'
            });
        }

        const authCollection = getAuthCollection();

        const user = await authCollection.findOne({ _id:  new ObjectId(userId) });
        if(!user){
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if(!user.isMailVerified){
            return res.status(403).json({ message: 'Email not verified. Cannot set pin.' });
        }
        
        if(!user.password){
            return res.status(469).json({ message: 'Setup Password for Password Login' });
        }

        const isPasswordValid = await comparePassword(password, user.password);
        if (!isPasswordValid) {
            return res.status(403).json({
                success: false,
                message: 'Invalid password'
            });
        }

        const hashedPin = await hashPassword(pin);

        await authCollection.updateOne(
            { _id: user._id },
            { $set: { pin: hashedPin, usesPin: true, lastUpdated: Date.now() } }
        );

        notifyPinUpdate(user.email, Date.now(), user.name, deviceInfo)
                .catch(err => console.error('Redis notification error:', err));

        return res.status(200).json({
            success: true,
            message: 'PIN has been reset successfully. You can now login using your password.'
        });
    }
    catch{
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.post('/reset-pin', jwt, async (req, res) => {
    try{
        const {deviceInfo} = req.body;
        const userId  = req.userId;

        if (!userId) {
            return res.status(400).json({
                error: 'Invalid user ID in token',
                code: 'INVALID_USER_ID'
            });
        }

        const authCollection = getAuthCollection();

        const user = await authCollection.findOne({ _id:  new ObjectId(userId) });
        if(!user){
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        await authCollection.updateOne(
            { _id: user._id },
            { $set: { pin: "", usesPin: false, lastUpdated: Date.now() } }
        );

        notifyPinUpdate(user.email, Date.now(), user.name, deviceInfo)
                .catch(err => console.error('Redis notification error:', err));

        return res.status(200).json({
            success: true,
            message: 'PIN has been reset successfully. You can now login using your password.'
        });
    }
    catch{
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.post('/forgot-password_1', async (req, res) => {
  try {
    const { email, deviceInfo } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Valid email is required' });
    }

    const authCollection = getAuthCollection();
    const existingUser = await authCollection.findOne({ email: email.trim() });
    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
        doesExists: false,
      });
    }

    // 4️⃣ Generate OTP
    const { generateOtpAndPush } = await import('../utils/verifyOtp.js');
    const otpResult = await generateOtpAndPush(email, deviceInfo);
    if (!otpResult.success) {
      return res.status(500).json({
        success: false,
        message: 'Failed to generate OTP',
        doesExists: true,
      });
    }
    // 5️⃣ Generate secure random passKey
    const passKey =
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15);

    const { storePasskey } = await import('../utils/passkey.js');
    
    // 6️⃣ Store passkey in Redis with auto-expiry
    const stored = await storePasskey(existingUser._id.toString(), passKey);
    if (!stored) {
      return res.status(500).json({
        success: false,
        message: 'Failed to store passkey',
        doesExists: true,
      });
    }

    // 7️⃣ Respond success + passKey
    
    return res.status(200).json({
      success: true,
      message: 'Verification OTP sent to your email',
      expirySeconds: otpResult.expirySeconds,
      doesExists: true,
      passKey, 
    });
  } 
  catch (err) {
    console.error('Error in /forgot-password_1:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


router.post('/forgot-password_2', async (req, res) => {
  try {
    const { email, password, confirmPassword, deviceInfo, passKey, otp } = req.body;
    if (!email || !password || !confirmPassword || !passKey || !otp) {
      return res.status(499).json({ message: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const VerifyPass = VerifyPassword(password);
    if (!VerifyPass) {
      return res.status(400).json({ message: 'Password does not meet criteria' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Valid email is required' });
    }

    const authCollection = getAuthCollection();
    const user = await authCollection.findOne({ email: email.trim() });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const { verifyUserOtp } = await import('../utils/verifyOtp.js');
    const verificationResult = await verifyUserOtp(email, otp);

    if (!verificationResult.success) {
      return res.status(400).json({
        success: false,
        message: verificationResult.message,
        attemptsRemaining: verificationResult.attemptsRemaining
      });
    }

    // Validate passkey using Redis
    const { verifyPasskey } = await import('../utils/passkey.js');
    const isValidPasskey = await verifyPasskey(user._id.toString(), passKey);
    
    if (!isValidPasskey) {
      return res.status(400).json({ message: 'Invalid or expired passkey' });
    }

    // ✅ Passkey valid — proceed to reset password
    const hashed = await hashPassword(password);

    await authCollection.updateOne(
      { _id: user._id },
      {
        $set: {
          password: hashed,
          pin: "",
          lastUpdated: Date.now(),
          usesPin: false
        }
      }
    );

    // Notify password update asynchronously
    notifyPasswordUpdate(user.email, Date.now(), user.name, deviceInfo)
      .catch(err => console.error('Redis notification error:', err));

    return res.status(200).json({
      success: true,
      message: 'Password reset successfully. Please verify your email again.'
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

router.post('/verifyemail', jwt, async (req, res) => {
    try {
        const { email, otp } = req.body;
        
        if (!email || !otp) {
            return res.status(400).json({
                success: false,
                message: 'Email and OTP are required'   
            });
        }
       
        const authCollection = getAuthCollection();
        const user = await authCollection.findOne({ email: email.trim() });
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        const { verifyUserOtp } = await import('../utils/verifyOtp.js');
        
        const verificationResult = await verifyUserOtp(user.email, otp);
        
        if (verificationResult.success) {
            await authCollection.updateOne(
                { _id: user._id },
                { $set: { 
                    isMailVerified: true,
                    lastUpdated: Date.now()
                }}
            );
            
            return res.status(200).json({
                success: true,
                message: 'Email verified successfully'
            });
        } 
        else {
            // Return error response with attempts remaining
            return res.status(400).json({
                success: false,
                message: verificationResult.message,
                attemptsRemaining: verificationResult.attemptsRemaining
            });
        }
    } 
    catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

router.post('/details', jwt, async (req, res) => {
    try{

        const userId  = req.userId;

        const authCollection = await getAuthCollection();
        const user = await authCollection.findOne({ _id : new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({
                error: 'User not found',
                code: 'USER_NOT_FOUND'
            });
        }

        const { password, pin,_id,  ...userDetails } = user; // Exclude password and pin and id
        res.status(200).json({ user: userDetails });
    }
    catch(err){
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.post('/check-username', jwt, async (req, res) => {
    try{
        const {username} = req.body;
        const userId  = req.userId;
        if (!userId) {
            return res.status(400).json({
                error: 'Invalid user ID in token',
                code: 'INVALID_USER_ID'
            });
        }

        const authCollection = getAuthCollection();
        const user = await authCollection.findOne({ _id:  new ObjectId(userId) });
        if(!user){
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        const isValid = validateUsernameFormat(username);
        if(!isValid){
            return res.status(400).json({ isUnique: false, message: 'Invalid username format' });
        }

        const existingUser = await authCollection.findOne({ username: username.trim() });
        if (existingUser) {
            return res.status(200).json({ isUnique: false, message: 'Username is already in use' });
        } 
        else {
            return res.status(200).json({ isUnique: true, message: 'Username is available' });
        }
    }
    catch(err){
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.put('/update-username', jwt, async (req, res) => {
    try{
        const {deviceInfo , username} = req.body;
        const  userId  = req.userId;
        if (!userId) {
            return res.status(400).json({
                error: 'Invalid user ID in token',
                code: 'INVALID_USER_ID'
            });
        }

        const authCollection = getAuthCollection();
        const user = await authCollection.findOne({ _id:  new ObjectId(userId) });
        if(!user){
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        const isValid = validateUsernameFormat(username);
        if(!isValid){
            return res.status(400).json({ isUnique: false, message: 'Invalid username format' });
        }

        const existingUser = await authCollection.findOne({ username: username.trim() });
        if (existingUser) {
            return res.status(200).json({ success: false, message: 'Username is already in use' });
        } 
        else {
            const temp = user.username;
            await authCollection.updateOne({ _id: user._id }, { $set: { username: username.trim(), lastUpdated: Date.now() } });
            // notify
            notifyUsernameUpdate(user.email, Date.now(), temp, username.trim(), deviceInfo,user.name)
            return res.status(200).json({ success: true, message: 'Username is available' });
        }
        
    }
    catch(err){
        
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.put('/logout', jwt, async (req, res) => {
    try {
        const { deviceInfo } = req.body;
        const userId = req.userId;

        const authCollection = await getAuthCollection();
        const user = await authCollection.findOne({ _id: new ObjectId(userId) });
        
        if (!user) return res.status(404).json({ message: 'User not found' });

        const ip = deviceInfo?.ip;
        let updatedHistory = (user.history || []).filter(h => h.ip !== ip);

        await authCollection.updateOne(
            { _id: user._id },
            { $set: { history: updatedHistory, lastUpdated: Date.now() } }
        );
        
        return res.status(200).json({ message: 'IP removed from history successfully' });

    }
     catch (err) {
        
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.put('/logout-all', jwt, async (req, res) => {
    try {
        const userId = req.userId;
        const authCollection = await getAuthCollection();
        await authCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { history: [], lastUpdated: Date.now() } }
        );

        res.status(200).json({ message: 'History cleared successfully' });
    } 
    catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

router.delete('/delete-account', jwt, async (req, res) => {
    try{
        const {password, deviceInfo} = req.body;
        if(!password){
            return res.status(400).json({
                success: false,
                message: 'Password is required'
            });
        }

        const userId  = req.userId;

        if (!userId) {
            return res.status(400).json({
                error: 'Invalid user ID in token',
                code: 'INVALID_USER_ID'
            });
        }

        const authCollection = getAuthCollection();
        const clipCollection = getClipCollection();
        const user = await authCollection.findOne({ _id:  new ObjectId(userId) });
        if(!user.password){
            return res.status(469).json({ message: 'Setup Password for Password Login' });
        }

        if(!user){
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const isPasswordValid = await comparePassword(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid password'
            });
        }

        // Proceed with account deletion
        try {
            // Delete user auth first
            const result1 = await authCollection.deleteOne({ _id: user._id });
            if (result1.deletedCount !== 1) {
                return res.status(500).json({
                    success: false,
                    message: 'Failed to delete account authentication'
                });
            }

            
            const userClip = await clipCollection.findOne({ id: (user._id.toString()) });
            if (!userClip) {
                return res.status(200).json({
                    success: true,
                    message: 'Account deleted successfully'
                });
            }
            // Delete associated clips
            const imageIds = userClip.image?.map((img) => img.publicId) || [];
            const fileIds = userClip.file?.map((file) => file.publicId) || [];

            // Delete from Cloudinary
            await Promise.all([
                imageIds.length > 0 ? deleteMultipleFiles(imageIds,'image') : Promise.resolve(null),
                fileIds.length > 0 ? deleteMultipleFiles(fileIds,'raw') : Promise.resolve(null),
            ]);

            // delete profiel pic
            if(user.profile){
                await deleteMultipleFiles([user.profile],'image');
            }
            const result2 = await clipCollection.deleteOne({ id: (user._id.toString()) });
            if (result2.acknowledged !== true) {
                // Try to rollback auth deletion
                await authCollection.insertOne(user);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to delete user clips'
                });
            }

            // Notify about account deletion through Redis
            await notifyAccountDelete(user.email, Date.now(), deviceInfo, user.name);

            return res.status(200).json({
                success: true,
                message: 'Account and all associated data deleted successfully'
            });
        } catch (error) {
            console.error('Account deletion error:', error);
            return res.status(500).json({
                success: false,
                message: 'Error during account deletion'
            });
        }

    }
    catch(err){
        
        res.status(500).json({ message: 'Internal server error' });
    }
});

export default router;
