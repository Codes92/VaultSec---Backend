
function validateHash(req, res, next)
{
    const {input, algorithm} = req.body;

    const allowedHashAlgorithms = new Set(['sha256', 'sha384', 'sha512']);

    if (!input || input.length < 1 || input.length > 10000)
    {
        return res.status(400).json({error: "Input must be a non-empty string of 10000 characters or less"});
    }

    if (!allowedHashAlgorithms.has(algorithm))
    {
        return res.status(400).json({error: "Hashing algorithm must be sha256, sha384, or sha512"});
    }

    next();
}

module.exports = {validateHash}