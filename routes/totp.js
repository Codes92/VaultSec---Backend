/** Routes for totp */
const express = require("express");
const router = express.Router();

const {challengeTotp} = require("../services/authService");
const {setupTotp, verifyTotp, disableTotpSecret, totpStatus} = require("../services/totpService");
const { isLoggedIn } = require("../middleware/validateAuth");

const rateLimit = require("express-rate-limit");
const totpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: {error: "Too many attempts, please try again later"}
});

router.post("/challenge", totpLimiter, async(req, res) => {
    try
    {
        const response = await challengeTotp(req.body.mfaPendingToken, req.body.code);

        res.cookie("token", response.token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 60 * 60 * 1000
        });
        res.json({email: response.email, kdfSalt: response.kdfSalt, message: "Login Successful"});
    }
    catch (error)
    {
        res.status(401).json({error: error.message});
    }
});

router.post("/setup", isLoggedIn, totpLimiter, async(req, res) => {
    try
    {
        const response = await setupTotp(req.user.userId);
        res.json({qrCode: response});
    }
    catch (error)
    {
        res.status(401).json({error: error.message});
    }
});

router.post("/verify", isLoggedIn, totpLimiter, async(req, res) => {
    try
    {
        const response = await verifyTotp(req.user.userId, req.body.code);
        res.json({valid: response});
    }
    catch (error)
    {
        res.status(400).json({error: error.message});
    }
});

router.post("/disable", isLoggedIn, totpLimiter, async(req, res) => {
    try
    {
        const response = await disableTotpSecret(req.user.userId, req.body.password);
        res.json({disabled: response});
    }
    catch (error)
    {
        res.status(401).json({error: error.message});
    }
});

router.get("/status", isLoggedIn, async(req, res) => {
    try
    {
        const response = await totpStatus(req.user.userId);
        res.json({status: response});
    }
    catch (error)
    {
        res.status(401).json({error: error.message});
    }
});

module.exports = router;