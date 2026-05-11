const crypto = require('crypto');

function generateHash(input, algorithm)
{
    const hash = crypto.createHash(algorithm).update(input).digest('hex');

    return {hash: hash, algorithm: algorithm};
}

module.exports = {generateHash};