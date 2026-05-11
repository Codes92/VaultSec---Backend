require('dns').setDefaultResultOrder('ipv4first');

/** Set up cors to enable cross-origin resource sharing
 * (requests from specific origin are allowed)
 * (also prevents other frontends talking to the API)
 */
require('dotenv').config();

const requiredEnvVars = [
    'JWT_SECRET',
    'TOTP_ENCRYPTION_KEY',
    'FRONTEND_URL',
    'DATABASE_URL'
    /*'DB_PASSWORD',
    'DB_NAME' */
];

/* 
    This crashes the app with a clear error in the event that
    and environment variable is missing
*/
for (const envVar of requiredEnvVars)
{
    if (!process.env[envVar])
    {
        console.error(`Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
}

const cors = require("cors");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");

const app = express();

app.set("trust proxy", 1);

const port = process.env.PORT || 8081;

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 attempts per window
    message: {error: "Too many attempts, please try again later"}
});

app.use(cors({origin: process.env.FRONTEND_URL, credentials: true}));
app.use(express.json());

app.use(helmet({
    referrerPolicy: {policy: "strict-origin-when-cross-origin"},
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true
    },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", process.env.FRONTEND_URL],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", process.env.FRONTEND_URL, "data:"],
            fontSrc: ["'self'"],
            connectSrc: ["'self'", process.env.FRONTEND_URL, "https://vaultsec-backend-production.up.railway.app"]
        }
    },
    crossOriginEmbedderPolicy: {policy: "require-corp"}
}));

app.use("/auth", authLimiter);
app.use(cookieParser());

const { contentSecurityPolicy } = require('helmet');
const { crossOriginEmbedderPolicy } = require('helmet');

// ========== ROUTE HANDLERS ===========
// Load the route handlers

const mainRoutes = require("./routes/main");
app.use("/", mainRoutes);

const authRoutes = require("./routes/auth");
app.use("/auth", authRoutes);

const totpRoutes = require ("./routes/totp"); // These routes are strongly connected to the auth routes
app.use("/auth/totp", totpRoutes);

const secRoutes = require("./routes/secrets");
app.use("/secrets", secRoutes);

const securityRoutes = require("./routes/security");
app.use("/security", securityRoutes);

const intelRoutes = require("./routes/intelligence");
app.use("/intelligence", intelRoutes);

process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection:', reason);
});

app.listen(port, () => console.log(`Node server is running on ${port}...`));