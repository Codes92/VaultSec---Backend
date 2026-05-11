/** Routes for authentication */
const express = require("express");
const router = express.Router();

/** Import auth services and middleware functions */
// Import auth services
const {registerUser, loginUser, changePasswordService, deleteUserAccount } = require("../services/authService");
// Import validation middleware
const {validateRegistration, validateLogin} = require("../middleware/validateUser");
const { isLoggedIn } = require("../middleware/validateAuth");

// =============== Registration ===============
// ============================================
router.post("/register", validateRegistration, async (req, res) => {
    try
    {
        const {token, email, kdfSalt} = await registerUser(req.body.email, req.body.password);

        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            /* secure: process.env.NODE_ENV === "production", */
            sameSite: "None",
            maxAge: 60 * 60 * 1000 // 1 hour
        });
        res.json({email, kdfSalt, message: "Registration Successful"});
    }
    catch (error)
    {
        res.status(400).json({error: error.message});
    }
});

// =============== Login ===============
// =====================================
router.post("/login", validateLogin, async(req, res) => {
    try
    {
        const response = await loginUser(req.body.email, req.body.password);
        if (response.mfaPendingToken)
        {
            return res.json({mfaPendingToken: response.mfaPendingToken, message: "TOTP required"});
        }

        res.cookie("token", response.token, {
            httpOnly: true,
            secure: true,
            /* secure: process.env.NODE_ENV === "production", */
            sameSite: "None",
            maxAge: 60 * 60 * 1000 // 1 hour
        });
        res.json({email: response.email, kdfSalt: response.kdfSalt, message: "Login Successful"});
    }
    catch (error)
    {
        res.status(401).json({error: error.message});
    }
});

// =============== Change Password ===============
// ===============================================
router.post("/change-password", isLoggedIn, async(req, res) => {
    try
    {
        const userId = req.user.userId;
        const currentPassword = req.body.currentPassword;
        const newPassword = req.body.newPassword;

        const response = await changePasswordService(userId, currentPassword, newPassword);

        res.json({message: "Password change successful!"});

    }
    catch (error)
    {
        res.status(401).json({error: error.message});
    }
});

// =============== Delete Account ===============
// ==============================================
router.delete("/delete-account", isLoggedIn, async(req, res) => {
    try
    {
        const userId = req.user.userId;
        const password = req.body.password;

        const response = await deleteUserAccount(userId, password);

        res.json({message: "Your account was successfully deleted."})
    }
    catch (error)
    {
        res.status(401).json({error: error.message});
    }
});

module.exports = router;