/** Validate authentication user input */
// This component contains reusable authentication functions to check if data is valid
// They are foundational functions that can be used by the middleware and around the application

const validator = require("validator");

// ===================== AUTHENTICATION VALIDATION ======================= \\
// ======================================================================= \\

/**
 * Validate and normalise user email address
 * @param {string} email
 * @returns {{valid: boolean, reason?: string, normalised?: string}}
 */
function isValidEmail(email)
{
    // Check that input is a string
    if (!email || typeof email !== "string")
    {
        return {valid: false, reason: "Email must be a non-empty string"};
    }

    // remove whitespaces from email input
    const trimmed = email.trim();
    // Check if email is valid
    if (!validator.isEmail(trimmed))
    {
        return {valid: false, reason: "Invalid email address"};
    }

    const normalised = validator.normalizeEmail(trimmed);

    return {valid: true, normalised};
};

/**
 * Validates user password against security requirements
 * @param {string} password 
 * @returns {{valid: boolean, reason?: string}}
 */
function isValidPassword(password)
{
    // Check password is a non-empty string
    if (!password || typeof password !== "string")
    {
        return {valid: false, reason: "Password must be a non-empty string"};
    }

    const MIN_PASSWORD_LENGTH = 8;
    const MAX_PASSWORD_LENGTH = 128;

    // Check max length first to prevent large input being handled by regex
    if (password.length > MAX_PASSWORD_LENGTH)
    {
        return {valid: false, reason: `Password must be at most ${MAX_PASSWORD_LENGTH} characters`};
    }

    // Enforce minimum password length
    if (password.length < MIN_PASSWORD_LENGTH)
    {
        return {valid: false, reason: `Password must be at least ${MIN_PASSWORD_LENGTH} characters`}
    }

    const requirements = {
        upperCase: /[A-Z]/.test(password),
        lowerCase: /[a-z]/.test(password),
        digit: /[0-9]/.test(password),
        specialChar: /[!@#$%^&*() _+=<>?/|{}\[\]\\;:'",.-]/.test(password)
    };
    
    // Loop through requirements object to check for non-compliance
    for (const [requirement, passed] of Object.entries(requirements))
    {
        if (!passed)
        {
            const messages = {
                upperCase: "Password must contain at least one uppercase letter.",
                lowerCase: "Password must contain at least one lowercase letter.",
                digit: "Password must contain at least one number.",
                specialChar: "Password must contain at least one special character."
            };
            // return false and reason why
            return {valid: false, reason: messages[requirement]};
        }
    }

    return {valid: true}
};

module.exports = {isValidEmail,
                  isValidPassword}