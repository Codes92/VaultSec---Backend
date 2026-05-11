const {isValidDomain} = require("../utils/sslValidator");

function validateDomain(req, res, next)
{
    const {domain} = req.body;

    const domainResult = isValidDomain(domain);
    if (!domainResult.valid)
    {
        return res.status(400).json({error: domainResult.reason});
    }

    req.sanitizedDomain = domainResult.check;

    next();
}

module.exports = {validateDomain};