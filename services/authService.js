/** Business logic layer between routes and models 
    Handles the following operations for authentication:
    - Takes data from routes
    - Performs business logic (hashing, JWT creation, validation)
    - Calls database models
    - Returns processed results
 */

const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const {verify} = require("otplib");

let DUMMY_HASH;
(async() => {DUMMY_HASH = await argon2.hash("dummy_password");})();

// Import User model to contact database
const User = require("../models/userModel");
// Import TOTP model to enable TOTP provision
const {TOTP} = require("../models/totpModel");

const {decryptSecret} = require("../utils/encryption");

/**
 * Complete user registration
 * @param {string} email - email address for registration
 * @param {string} password - password for registration
 * @returns {{token: string, email: string, string}}
 */
async function registerUser(email, password)
{
    /** Validate email */
    if (await User.findByEmail(email))
    {
        throw new Error("Email already registered.");
        /**
         This error message is caught by the route
         catch (error) {res.status(400).send(error.message <---)}
         THEN
         The frontend (React component receives it)
         catch (error) {setError(error.message <---)}
         THEN
         JSX displays {error && <p>{error}</p>}
         */
    };

    const kdfSalt = crypto.randomBytes(32).toString("hex"); // Generate a random salt to attach to the password when hashed

    const hash = await argon2.hash(password); // Hash password

    // Create user
    const newUser = await User.createUser(email, hash, kdfSalt); // Call user model, which calls database to create the new user
    // Server creates token (the login session)
    // Creates better UX having token creation in registration as well as login (no second login)
    const token = jwt.sign({userId: newUser.id, email: newUser.email},
                            process.env.JWT_SECRET, {expiresIn: '1h'});
                            /** Tokens are verified in the isLoggedIn middleware */
    
    return {token: token, email: newUser.email, kdfSalt};
};

/**
 * Change user password
 * @param {string} currentPassword - password
 * @returns {{token: string}}
 */
async function changePasswordService(id, currentPassword, newPassword)
{

    const user = await User.findById(id);

    // Verify user-entered password against the actual password in db
    const match = await argon2.verify(user.hashed_login_verifier, currentPassword);
    if (!match)
    {
        throw new Error("Invalid password");
    };

    const hash = await argon2.hash(newPassword); // Hash password

    const changed = await User.changePassword(id, hash);

    return changed;
}

/**
 * Complete user login (post registration)
 * @param {string} email - email address for login
 * @param {string} password - password for login
 * @returns {{token: string, email: string, string}}
 */
async function loginUser(email, password)
{
    const user = await User.findByEmail(email);
    
    // Check user exists in database
    if (!user)
    {
        await argon2.verify(DUMMY_HASH || await argon2.hash("dummy_password"), password); // burn time
        throw new Error("Invalid credentials");
        // Again ^^ this message will be seen by end users
    };

    // Compare passwords
    const match = await argon2.verify(user.hashed_login_verifier, password);
    if (!match)
    {
        throw new Error("Invalid credentials");
        // Security purposes - Don't disclose what exactly was invalid
    };

    const totpEnabled = user.totp_enabled;
    let token;
    
    if (totpEnabled)
    {
        token = jwt.sign({userId: user.id, email: user.email, type: 'mfa_pending'},
                             process.env.JWT_SECRET, {expiresIn: '2m'});
        return {mfaPendingToken: token};
    }
    else
    {
        // Create token for user login session
        token = jwt.sign({userId: user.id, email: user.email},
                                process.env.JWT_SECRET, {expiresIn: '1h'});
        return {token: token, email: user.email, kdfSalt: user.kdf_salt};
    }
};

/**
 * Verifies a TOTP code for a user with pending MFA and issues a login token
 * @param {string} mfaPendingToken - JWT inficating MFA is required
 * @param {string} code - TOTP code provided by the user
 * @returns {{token: string, email: string, kdfSalt: string}}
 */
async function challengeTotp(mfaPendingToken, code)
{
    try
    {
        if (!code || typeof code !== "string")
        {
            throw new AuthError("Invalid input");
        }

        // Ensure token is valid and not tampered with
        const decoded = jwt.verify(mfaPendingToken, process.env.JWT_SECRET);
        // Confirm token is specifically for MFA flow
        if (decoded.type !== "mfa_pending")
        {
            throw new Error("Invalid token");
        }
        
        const userId = decoded.userId;
        // Load authentication data
        const user = await User.findById(userId);
        const totp = await TOTP.findTotpSecret(userId);
        // Prevent crash in the event user or totp doesn't exist
        if (!user || !totp)
        {
            throw new Error("User or TOTP data not found");
        }

        if (!totp?.totp_secret)
        {
            throw new AuthError("TOTP not configured");
        }

        const [ciphertext, iv, authTag] = totp.totp_secret.split(":"); // Extract encryption components

        const decrypted = decryptSecret(ciphertext, iv, authTag); // Recover raw shared secret

        // Prevent reuse of same TOTP code
        if (code === user.totp_last_used_code)
        {
            throw new Error("Reused code error");
        }
        // Validate code against secret
        const result = await verify({token: code, secret: decrypted});

        if (!result)
        {
            throw new Error("Invalid code error");
        }

        await TOTP.updateTotpVerification(userId, code); // Update state to prevent reuse

        // Create token for user login session
        const token = jwt.sign({userId: user.id, email: user.email}, // Grant authenticated session
                                process.env.JWT_SECRET, {expiresIn: '1h'});
        return {token: token, email: user.email, kdfSalt: user.kdf_salt};
    }
    catch (error)
    {
        throw error;
    }
};

async function deleteUserAccount(id, password)
{
    const user = await User.findById(id);

    // Verify user-entered password against the actual password in db
    const match = await argon2.verify(user.hashed_login_verifier, password);
    if (!match)
    {
        throw new Error("Invalid password");
    };

    const deleted = await User.deleteAccount(id);

    return deleted;
}

module.exports = {registerUser,
                  loginUser,
                  challengeTotp,
                  changePasswordService,
                  deleteUserAccount}