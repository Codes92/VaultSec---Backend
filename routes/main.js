/** Homepage routes */
const express = require("express");
/** Router object for exporting */
const router = express.Router();

router.get("/", (req, res) => {
    res.send("This is the homepage");    
})

module.exports = router;