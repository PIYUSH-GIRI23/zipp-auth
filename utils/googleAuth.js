import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { getAuthCollection } from '../db/init.js';
import { ObjectId } from 'mongodb';
import { generateUniqueUsername , validateUsernameFormat } from './usernameGenerator.js';
const configureGoogleStrategy = () => {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
        passReqToCallback: true
    }, async (req, accessToken, refreshToken, profile, done) => {
        try {
            const authCollection = getAuthCollection();
            const deviceInfo = req.query.state ? JSON.parse(decodeURIComponent(req.query.state)) : {};
            const currentTime = Date.now();
            const email = profile.emails[0].value;


            let user = await authCollection.findOne({ email });

            if (user) {
                // ----- EXISTING USER -----
               let history = user.history || [];
                if (deviceInfo && deviceInfo.ip) {
                    const existing = history.find(h => h.ip === deviceInfo.ip);
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
                    if (existing) {
                        existing.data = newEntry.data;
                    } else {
                        history.push(newEntry);
                    }
                }


                // Update user document
                await authCollection.updateOne(
                    { email },
                    {
                        $set: {
                            lastLogin: currentTime,
                            lastUpdated: currentTime,
                            googleId: profile.id,
                            history
                        }
                    }
                );

                user.history = history;
                user.lastLogin = currentTime;
                user.lastUpdated = currentTime;
                return done(null, { user, isNewUser: false, deviceInfo });
            }

            // ----- NEW USER -----
            const names = profile.displayName.split(' ');
            const firstName = names[0].charAt(0).toUpperCase() + names[0].slice(1).toLowerCase();
            const lastName = names.slice(1).map(name => name.charAt(0).toUpperCase() + name.slice(1).toLowerCase()).join(' ');
            const username = await generateUniqueUsername(authCollection, firstName, lastName);

            const history = [];
            if (deviceInfo && deviceInfo.ip) {
                history.push({
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
            } else {
                console.log("=== No Device Info Provided for History ===");
            }

            const newUser = {
                firstName,
                lastName,
                name: firstName + (lastName ? ' ' + lastName : ''),
                email,
                username,
                googleId: profile.id,
                dateOfJoining: currentTime,
                lastUpdated: currentTime,
                lastLogin: currentTime,
                pin: '',
                isMailVerified: true,
                usesPin: false,
                profile: profile.photos?.[0]?.value || '',
                accountPlan: 1,
                history,
                password: '',
                SignupType: 'google'
            };

         

            const result = await authCollection.insertOne(newUser);
            
            // Verify the inserted user
            const insertedUser = await authCollection.findOne({ _id: result.insertedId });


            return done(null, { user: { ...newUser, _id: result.insertedId }, isNewUser: true, deviceInfo });

        } catch (error) {
            console.error('Google strategy error:', error);
            return done(error, null);
        }
    }));

    return passport;
};

export const setupGoogleAuth = () => {
    configureGoogleStrategy();
    return passport;
};
