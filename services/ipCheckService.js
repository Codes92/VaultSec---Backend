
async function ipCheck(ipAddress)
{
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ipAddress}`, {
        headers: {
            Key: process.env.ABUSEIPDB_API_KEY
        }
    });

    const {data: ipData} = await response.json();

    const relevantFields = {
        "confidenceScore": ipData.abuseConfidenceScore,
        "country": ipData.countryCode,
        "isp": ipData.isp,
        "totalReports": ipData.totalReports,
        "lastReport": ipData.lastReportedAt,
        "whitelisted": ipData.isWhiteListed
    };

    return relevantFields;
}

module.exports = {ipCheck}