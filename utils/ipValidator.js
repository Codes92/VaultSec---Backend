/** IP authentication user input */
// This component contains reusable IP checking functions to check if data is valid
// They are foundational functions that can be used by the middleware and around the application

const net = require("net");

// ====================== IP VALIDATION ======================== \\
// ============================================================= \\

/**
 * Validate and normalise IP input
 * @param {string} domain - user-input IP
 * @returns {{valid: boolean, reason?: string or check:sanitizedDomain}}
 */
function isValidIP(ipAddress)
{
    // Check IP is a non-empty string
    if (!ipAddress)
    {
        return {valid: false, reason: "IP address name must be a non-empty string"};
    }

    // Convert IP to lowercase before sanitization and validation
    // Only applicable to IPv6
    const base = ipAddress.toLowerCase();

    /** ============ 1. Sanitization ============ */
    // Remove whitespace
    const trimmed = base.trim();

    const checkIPv4 = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(trimmed);

    // Regex for IPv6 is worth storing, but very complex
    const checkIPv6 = net.isIPv6(trimmed);

    if (!checkIPv4 && !checkIPv6)
    {
        return {valid: false, reason: "IP must be a valid IPv4 or IPv6 address"};
    }

    return {valid: true, check: trimmed};
}

module.exports = {isValidIP};