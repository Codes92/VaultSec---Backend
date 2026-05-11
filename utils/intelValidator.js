/** Validate intelligence user input */
// This component contains reusable authentication functions to check if data is valid
// They are foundational functions that can be used by the middleware and around the application

/**
 * Validate user input to cve-search
 * @param {string} product
 * @returns {valid: boolean, reason?: string}
 */
function isValidCVEInput(product)
{
    // Remove whitespace
    const trimmed = product.trim();

    // Ensure product input is non-empty and correct type
    if (!product || product.length === 0 || typeof(product) !== "string")
    {
        return {valid: false, reason: "Product must be a non-empty string"};
    }

    // Impose max length of product input
    if (product.length > 100)
    {
        return {valid: false, reason: "Product name cannot be more than 100 characters"};
    }

    if (!/^[A-Za-z0-9-_ ]+$/.test(trimmed))
    {
        return {valid: false, reason: "Invalid CVE search"};
    }

    return {valid: true, check: trimmed};
}