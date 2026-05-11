
async function cveSearch(cveSearch, cveType)
{
    let response;

    if (cveType === "id")
    {
        response = await fetch(`https://api.osv.dev/v1/vulns/${cveSearch}`);
    }

    /*
    if (cveType === "keyword")
    {
        response = await fetch(`https://api.osv.dev/v1/query`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({query: cveSearch})
        });
    } */

    if (!response)
    {
        throw new Error("Invalid CVE search type");
    }

    const data = await response.json();

    const responseObject = 
    {
        id: data.id,
        summary: data.summary,
        details: data.details,
        aliases: data.aliases || [],
        published: data.published,
        modified: data.modified,
        severity: data.severity?.[0]?.score || "Unknown",
        references: data.references?.map(ref => ({
            type: ref.type,
            url: ref.url
        })) || [],
        affectedPackages: data.affected?.map(pkg => ({
            ecosystem: pkg.package?.ecosystem,
            name: pkg.package?.name
        })) || []
    }

    return responseObject;
}

module.exports = {cveSearch};