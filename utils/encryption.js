/** Encryption helper module */

// import crypto module
const crypto = require('crypto');

/**
 * Encrypts a plaintext password using AES-256-GCM before storing them in the database
 * @param {string} password
 * @returns {{ciphertext: string, iv: string, authTag: string}}
 */
function encryptSecret(password)
{
    const key = process.env.TOTP_ENCRYPTION_KEY; // Reads encryption key from env
    const buffer = Buffer.from(key, "hex"); // Converts hex string into binary buffer (crypto API requires raw bytes) 
    
    const generatedIV = crypto.randomBytes(12); // Generates random initialization vector (12 bytes for AES-GCM)

    const ciphertext = crypto.createCipheriv("aes-256-gcm", buffer, generatedIV); // Creates cipher instance
    // Encrypt password
    const encrypted = Buffer.concat([ciphertext.update(password, 'utf8'), ciphertext.final()]); // update --> process input, final --> complete encryption

    const authTag = ciphertext.getAuthTag(); // retrieves authentication tag for verification during decryption

    // Returns object containing ciphertext, iv, and authTag
    return {
        // Encrypted outputs are in raw binary data.
        // Base 64 makes them safe to store + transmit as text and safe for JSON/APIs (no encoding problems)
        ciphertext: encrypted.toString('base64'), // Encrypted data
        iv: generatedIV.toString('base64'), // IV required for decryption
        authTag: authTag.toString('base64') // Verifies authenticity
    };
}

/**
 * Decrypts a secret using AES-256-GCM
 * @param {string} ciphertext - Base64 encoded ciphertext
 * @param {string} iv - Base64 encoded initialization vector
 * @param {string} authTag - Base64 encoded authentication tag
 * @returns {string}
 */
function decryptSecret(ciphertext, iv, authTag)
{
    const key = process.env.TOTP_ENCRYPTION_KEY;
    const buffer = Buffer.from(key, "hex");

    const cipherTextBuffer = Buffer.from(ciphertext, 'base64'); // Decode Base64 ciphertext into raw bytes
    const IVBuffer = Buffer.from(iv, 'base64'); 
    const authTagBuffer = Buffer.from(authTag, 'base64');

    const decipher = crypto.createDecipheriv("aes-256-gcm", buffer, IVBuffer); // Create decipher instance with algorithm, key, and IV
    decipher.setAuthTag(authTagBuffer); // Set authentication tag to verify integrity

    const decrypted = Buffer.concat([decipher.update(cipherTextBuffer), decipher.final()]); // update --> process input, final --> complete decryption

    return decrypted.toString('utf-8');
}

module.exports = {encryptSecret, decryptSecret};