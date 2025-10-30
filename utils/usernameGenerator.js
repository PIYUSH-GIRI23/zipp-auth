export const generateRandomUsername = (length = null, prefix = '') => {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const underscore = '_';
  
    const allChars = uppercase + lowercase + numbers + underscore;
    
    const usernameLength = length || Math.floor(Math.random() * 5) + 8; // 8-12 characters
    
    let username = prefix;
    let remainingLength = usernameLength - prefix.length;
    
    if (remainingLength >= 4) {
        username += uppercase[Math.floor(Math.random() * uppercase.length)];
        username += lowercase[Math.floor(Math.random() * lowercase.length)];
        username += numbers[Math.floor(Math.random() * numbers.length)];
        username += underscore;
        remainingLength -= 4;
    }
    
    for (let i = 0; i < remainingLength; i++) {
        username += allChars[Math.floor(Math.random() * allChars.length)];
    }
    
    if (prefix.length > 0) {
        const prefixPart = username.slice(0, prefix.length);
        const randomPart = username.slice(prefix.length).split('').sort(() => Math.random() - 0.5).join('');
        username = prefixPart + randomPart;
    } 
    else {
        username = username.split('').sort(() => Math.random() - 0.5).join('');
    }
    
    return username;
};

export const generateUsernameFromName = (firstName, lastName = '') => {

    const cleanFirstName = firstName.toLowerCase().replace(/[^a-z]/g, '');
    const cleanLastName = lastName.toLowerCase().replace(/[^a-z]/g, '');
    
    let base = '';
    if (cleanFirstName.length >= 3) {
        base = cleanFirstName.slice(0, 3);
    } 
    else {
        base = cleanFirstName;
    }
    
    if (cleanLastName.length >= 2) {
        base += cleanLastName.slice(0, 2);
    }
    
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const underscore = '_';
    
    const randomSuffix = 
        uppercase[Math.floor(Math.random() * uppercase.length)] +
        numbers[Math.floor(Math.random() * numbers.length)] +
        underscore +
        numbers[Math.floor(Math.random() * numbers.length)] +
        numbers[Math.floor(Math.random() * numbers.length)];
    
    return base + randomSuffix;
};

export const generateUsernameOptions = (firstName, lastName = '', count = 3) => {
    const options = [];
    
    options.push(generateUsernameFromName(firstName, lastName));
    
    for (let i = 1; i < count; i++) {
        options.push(generateRandomUsername());
    }
    
    return options;
};


export const validateUsernameFormat = (username) => {
    if (username.length < 3 || username.length > 30) {
        return false;
    }
    
    const allowedPattern = /^[a-zA-Z0-9_-]+$/;
    if (!allowedPattern.test(username)) {
        return false;
    }
    
    return true;
};

export const generateUniqueUsername = async (authCollection, firstName, lastName = '', maxAttempts = 10) => {
    let attempts = 0;
    
    while (attempts < maxAttempts) {
        const username = attempts === 0 
            ? generateUsernameFromName(firstName, lastName)
            : generateRandomUsername();
        
        const existingUser = await authCollection.findOne({ username });
        
        if (!existingUser) {
            return username;
        }
        
        attempts++;
    }
    
    const timestamp = Date.now().toString().slice(-6);
    const fallbackUsername = `user_${timestamp}`;
    
    return fallbackUsername;
};

export default {
    generateRandomUsername,
    generateUsernameFromName,
    generateUsernameOptions,
    validateUsernameFormat,
    generateUniqueUsername
};