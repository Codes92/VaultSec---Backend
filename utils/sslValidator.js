/** SSL/TLS authentication user input */
// This component contains reusable SSL/TLS checking functions to check if data is valid
// They are foundational functions that can be used by the middleware and around the application

// ====================== SSL CHECKING VALIDATION ======================== \\
// ======================================================================= \\

/**
 * Validate and normalise user email address
 * @param {string} domain - user-input domain name
 * @returns {{valid: boolean, reason?: string or check:sanitizedDomain}}
 */
function isValidDomain(domain)
{
    // Check domain is a non-empty string
    if (!domain)
    {
        return {valid: false, reason: "Domain name must be a non-empty string"};
    }

    // Convert domain to lowercase before sanitization and validation
    const base = domain.toLowerCase();

    /** ============ 1. Sanitization ============ */
    // Remove whitespace
    const trimmed = base.trim();

    // Remove HTTPS: or HTTP:
    const removeHTTP = trimmed.replace("http://", '');
    const removeHTTPS = removeHTTP.replace("https://", '');

    // Remove "www." prefix
    const prefixRemove = removeHTTPS.replace("www.", '');

    // Remove trailing slashes and port numbers
    const removeSlashes = prefixRemove.replace(/[:\/].*$/, '');

    // Change domain to lowercase
    const sanitizedDomain = removeSlashes.toLowerCase();


    /** ============ 2. Validation ============ */
    // Check domain is non-empty
    if (!sanitizedDomain || sanitizedDomain.length === 0)
    {
        return {valid: false, reason: "Domain name must be a non-empty string"};
    }

    // Check max length
    if (sanitizedDomain.length > 253)
    {
        return {valid: false, reason: "Domain name must be fewer than 254 characters"};
    }

    // Contains only valid characters
    if (!/^[a-z0-9.-]+$/.test(sanitizedDomain))
    {
        return {valid: false, reason: "Domain name must only contain letters, numbers, hyphens or dots"};
    }


    // Check first/last characters are not hyphens or dots
    const firstChar = sanitizedDomain.charAt(0);
    const lastChar = sanitizedDomain.charAt(sanitizedDomain.length - 1);
    if (firstChar === '-' || lastChar === '-' || firstChar === '.' || lastChar === '.')
    {
        return {valid: false, reason: "Domain name must not start or end with a hyphen or dot"};
    }

    // Ensure the domain is two parts separated by a dot
    if (!sanitizedDomain.includes('.'))
    {
        return {valid: false, reason: "Domain name must contain a dot separating two parts"};
    }

    // Check each section of domain name is between 1 and 63 characters
    const domainSplit = sanitizedDomain.split('.');
    for (let i = 0; i < domainSplit.length; ++i)
    {
        if (domainSplit[i].length < 1 || domainSplit[i].length > 63)
        {
            return {valid: false, reason: "Domain name parts must be between 1 and 63 characters"};
        }
    }

    // Check the TLD name is acceptable length
    const lastDot = sanitizedDomain.lastIndexOf('.');
    const tld = sanitizedDomain.substring(lastDot + 1);
    if (tld.length < 2)
    {
        return {valid: false, reason: "TLD name must be between 2 and 63 characters"};
    }

    // Check domain name doesn't contain consecutive dots
    if (/\.\./.test(sanitizedDomain))
    {
        return {valid: false, reason: "Domain name cannot contain consecutive dots"};
    }

    return {valid: true, check: sanitizedDomain};
}

module.exports = {isValidDomain};