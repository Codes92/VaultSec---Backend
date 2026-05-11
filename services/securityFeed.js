const Parser = require("rss-parser");

let cachedFeed = null;
let cachedTimestamp = null;

async function securityFeed()
{
    const thirtyMinutes = 30 * 60 * 1000;

    if (cachedFeed && cachedTimestamp && (Date.now() - cachedTimestamp < thirtyMinutes))
    {
        return cachedFeed;
    }

    const rssParser = new Parser();

    const cisaFeed = await rssParser.parseURL("https://www.cisa.gov/cybersecurity-advisories/all.xml");
    const cisaItems = cisaFeed.items.map(item => ({...item, source: "CISA"}));

    const krebsFeed = await rssParser.parseURL("https://krebsonsecurity.com/feed/");
    const krebsItems = krebsFeed.items.map(item => ({...item, source: "Krebs on Security"}));

    const bleepFeed = await rssParser.parseURL("https://www.bleepingcomputer.com/feed/");
    const bleepItems = bleepFeed.items.map(item => ({...item, source: "BleepingComputer"}));

    const result = [...cisaItems, ...krebsItems, ...bleepItems];

    const sorted = result.sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));

    cachedFeed = sorted;
    cachedTimestamp = Date.now();

    return sorted;
}

module.exports = {securityFeed};