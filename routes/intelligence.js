/** Routes for authentication */
const express = require("express");
const { securityFeed } = require("../services/securityFeed");
const { isLoggedIn } = require("../middleware/validateAuth");
const { cveSearch } = require("../services/cveSearchService");
const router = express.Router();

router.post("/cve-search", async (req, res) => {

    try
    {
        const search = req.body.search;
        const type = req.body.type;

        const response = await cveSearch(search, type);

        res.json({...response});
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

router.get("/news", isLoggedIn, async (req, res) => {
    try
    {
        const feed = await securityFeed();

        res.json({feed});
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

module.exports = router;