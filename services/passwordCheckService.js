
const {createHash} = require("crypto");

async function breachedPasswordCheck(password)
{
    const hash = createHash("sha1").update(password).digest("hex").toUpperCase();

    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const url = `https://api.pwnedpasswords.com/range/${prefix}`;

    const response = await fetch(url, {
        headers: {
            "Add-Padding": "true"
        }
    });

    if (!response.ok)
    {
        throw new Error({status: "unavailable"});
    }

    const data = await response.text();

    let splitData = data.split('\n');

    for (let i = 0; i < splitData.length; i++)
    {
        let line = splitData[i].trim();
        const lineData = line.split(':');

        if (lineData[0] === suffix)
        {
            return {compromised: true, count: parseInt(lineData[1], 10)};
        }
    }

    return {compromised: false};
}

module.exports = {breachedPasswordCheck};