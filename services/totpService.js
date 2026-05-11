const { TOTP: TotpLib, generateSecret, generateURI, verify } = require("otplib");
const QRCode = require("qrcode");

// Import User model to contact database
const User = require("../models/userModel");
// Import TOTP model to enable TOTP provision
const {TOTP} = require("../models/totpModel");
const { encryptSecret, decryptSecret } = require("../utils/encryption");
const argon2  = require("argon2");

async function setupTotp(userId)
{
    const totpSecret = generateSecret();

    const {ciphertext, iv, authTag} = encryptSecret(totpSecret);

    await TOTP.updateTotpSecret(userId, ciphertext, iv, authTag);

    const user = await User.findById(userId);

    const qrCodeURI = generateURI({ account: user.email, issuer: "VaultSec", secret: totpSecret });

    const qrImage = await QRCode.toDataURL(qrCodeURI);

    return qrImage;
};

async function verifyTotp(userId, code)
{
    try
    {
        const userSecret = await TOTP.findTotpSecret(userId);

        const [ciphertext, iv, authTag] = userSecret.totp_secret.split(":");

        const decrypted = decryptSecret(ciphertext, iv, authTag);

        const isValid = verify({token: code, secret: decrypted});

        if (isValid)
        {
            const timestamp = new Date();

            await TOTP.enableTotp(userId, timestamp);
        }

        return isValid;
    }
    catch (error)
    {
        throw new Error("Invalid input");
    }
}

async function disableTotpSecret(userId, password)
{
    const user = await User.findById(userId);

    // Compare passwords
    const match = await argon2.verify(user.hashed_login_verifier, password);
    if (!match)
    {
        throw new Error("Invalid credentials");
        // Security purposes - Don't disclose what exactly was invalid
    };

    await TOTP.disableTotp(userId);
}

async function totpStatus(userId)
{
    const user = await User.findById(userId);

    return user.totp_enabled;
}

module.exports = {setupTotp,
                  verifyTotp,
                  disableTotpSecret,
                  totpStatus
};