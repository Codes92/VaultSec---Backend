
function validateCVE(req, res, next)
{
    const {cveSearch} = req.body;

    // Check CVE search is non-empty
    if (!cveSearch)
    {
        return res.status(400).json({error: "Input must be one character or more"});
    }

    // Check CVE search is fewer than 100 characters
    if (cveSearch.length > 100)
    {
        return res.status(400).json({error: "Input must be fewer than 100 characters"});
    };

    // Check CVE search is a CVE lookup
    const cveInput = /^CVE-[0-9]{4}-[0-9]{5}$/.test(cveSearch);
    if (cveInput)
    {
        req.cveSearch = cveSearch;
        req.cveType = "id"; 
        next();
    }

    const charCheck = /[a-zA-Z0-9- ]+$/.test(cveSearch);
    if (!charCheck)
    {
        return res.status(400).json({error: "Input must contain only letters, numbers, hyphens or spaces"});
    }

    req.cveSearch = cveSearch;
    req.cveType = cveInput ? "id" : "keyword";

    next();
}