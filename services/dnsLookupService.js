async function dnsLookup(domain)
{
    const url = `https://cloudflare-dns.com/dns-query`;

    const AResponse = await fetch(`${url}?name=${domain}&type=A`, {
        headers: {
            "Accept": "application/dns-json"
        }
    });

    const AData = await AResponse.json();
    const ARecords = AData.Answer || []; 

    const MXResponse = await fetch(`${url}?name=${domain}&type=MX`, {
        headers: {
            "Accept": "application/dns-json"
        }
    });

    const MXData = await MXResponse.json();
    const MXRecords = MXData.Answer || [];

    const TXTResponse = await fetch(`${url}?name=${domain}&type=TXT`, {
        headers: {
            "Accept": "application/dns-json"
        }
    });

    const TXTData = await TXTResponse.json();
    const TXTRecords = TXTData.Answer || [];

    const NSResponse = await fetch(`${url}?name=${domain}&type=NS`, {
        headers: {
            "Accept": "application/dns-json"
        }
    });

    const NSData = await NSResponse.json();
    const NSRecords = NSData.Answer || [];

    return {aRecords: ARecords, mxRecords: MXRecords, txtRecords: TXTRecords, nsRecords: NSRecords};
}

module.exports = {dnsLookup};