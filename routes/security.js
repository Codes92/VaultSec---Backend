/** Routes for security */
const express = require("express");
const router = express.Router();

const { isLoggedIn } = require("../middleware/validateAuth");
const { validateDomain } = require("../middleware/validateDomain");
const { breachedPasswordCheck } = require("../services/passwordCheckService");
const { sslCheck } = require("../services/sslCheckService");
const { isValidPassword } = require("../utils/authValidator");
const { generateHash } = require("../services/hashService");
const { validateHash } = require("../middleware/validateHash");
const { dnsLookup } = require("../services/dnsLookupService");
const { httpHeadersAnalyzer } = require("../services/httpHeadersService");

const rateLimit = require("express-rate-limit");
const { validateIP } = require("../middleware/validateIP");
const { ipCheck } = require("../services/ipCheckService");
const sslDnsLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 attempts per window
    message: {error: "Too many attempts, please try again later"}
});

const hashGeneratorLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 30, // 30 attempts per window
    message: {error: "Too many attempts, please try again later"}
});

const cveLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: {error: "Too many attempts, please try again later"}
})

router.post("/password-check", isLoggedIn, async(req, res) => {
    try
    {
        // const userId = 1 <-- Testing
        // const userId = req.user.userId;
        const { password } = req.body;
        const validPassword = isValidPassword(password);

        if (!validPassword.valid)
        {
            return res.status(400).json(validPassword);
        }

        const checked = await breachedPasswordCheck(password);

        res.json({valid: true,
                  ...checked
        });
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});


router.post("/ssl-check", isLoggedIn, sslDnsLimiter, validateDomain, async(req, res) => {
    try
    {
        const validated = await sslCheck(req.sanitizedDomain);
        
        res.json({valid: true,
                  ...validated
        });
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

router.post("/hash", isLoggedIn, hashGeneratorLimiter, validateHash, async(req, res) => {
    try
    {
        const result = await generateHash(req.body.input, req.body.algorithm);

        res.json({hash: result.hash,
                  algorithm: result.algorithm
        });
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

router.post("/dns-lookup", isLoggedIn, sslDnsLimiter, validateDomain, async(req, res) => {
    try
    {
        const lookup = await dnsLookup(req.body.domain);

        res.json({
            aRecords: lookup.aRecords,
            mxRecords: lookup.mxRecords,
            txtRecords: lookup.txtRecords,
            nsRecords: lookup.nsRecords
        });
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

router.post("/headers", isLoggedIn, sslDnsLimiter, validateDomain, async(req, res) => {
    try
    {
        const response = await httpHeadersAnalyzer(req.body.domain);

        res.json({
            headers: response[0],
            securityHeaders: response[1]
        });
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

router.post("/ip-reputation", isLoggedIn, validateIP, sslDnsLimiter, async(req, res) => {
    try
    {
        const response = await ipCheck(req.approvedIP);

        res.json({
            confidenceScore: response.confidenceScore,
            country: response.country,
            isp: response.isp,
            totalReports: response.totalReports,
            lastReport: response.lastReport,
            whitelisted: response.whitelisted
        }); // ^^ Instead of the above, {...response} could just be returned instead
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

module.exports = router;