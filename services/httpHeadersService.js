async function httpHeadersAnalyzer(domain)
{
    const response = await fetch(`https://${domain}`, {
        method: "HEAD"
    });

    const headers = Object.fromEntries(response.headers);

    const securityHeaders = {
        "content-security-policy": headers["content-security-policy"] || null,
        "strict-transport-security": headers["strict-transport-security"] || null,
        "x-frame-options": headers["x-frame-options"] || null,
        "x-content-type-options": headers["x-content-type-options"] || null,
        "referrer-policy": headers["referrer-policy"] || null,
        "permissions-policy": headers["permissions-policy"] || null
    } 

    return [headers, securityHeaders];
}

module.exports = {httpHeadersAnalyzer};