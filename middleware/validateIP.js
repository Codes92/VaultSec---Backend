const { isValidIP } = require("../utils/ipValidator");

function validateIP(req, res, next)
{
    const {ipAddress} = req.body;

    const ipResult = isValidIP(ipAddress);
    if (!ipResult.valid)
    {
        return res.status(400).json({error: ipResult.reason});
    }

    req.approvedIP = ipResult.check;

    next();
}

module.exports = {validateIP};