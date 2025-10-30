const VerifyPassword = (password) => {
    if (password.length < 8) {
        return false;
    }

    // Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character
    const uppercasePattern = /[A-Z]/;
    const lowercasePattern = /[a-z]/;
    const digitPattern = /[0-9]/;
    const specialCharPattern = /[!@#$%^&*(),.?":{}|<>]/;

    if (!uppercasePattern.test(password)) {
        return false;
    }
    if (!lowercasePattern.test(password)) {
        return false;
    }
    if (!digitPattern.test(password)) {
        return false;
    }
    if (!specialCharPattern.test(password)) {
        return false;
    }

    return true;
};



export default VerifyPassword;