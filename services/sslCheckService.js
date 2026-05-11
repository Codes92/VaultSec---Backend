const { connect } = require('node:tls');

async function sslCheck(sslAddress)
{
    try
    {
        return new Promise((resolve, reject) => {
            const socket = connect(443, sslAddress, {rejectUnauthorized: true, servername: sslAddress}, () => {

                const certificate = socket.getPeerCertificate();

                if (!certificate || Object.keys(certificate).length === 0)
                {
                    reject("This certificate doesn't exist or can't be found");
                }

                const subject = {...certificate.subject};
                const subjectAltName = certificate.subjectaltname;
                const issuer = {...certificate.issuer};

                const validFrom = new Date(certificate.valid_from);
                const validUntil = new Date(certificate.valid_to);
                const today = new Date();

                let currentlyValid = true;
                if (!(today > validFrom && today < validUntil))
                {
                    currentlyValid = false;
                }
                
                const currentTLSVersion = socket.getProtocol();
                if (currentTLSVersion == null)
                {
                    reject("The current TLS version cannot be found");
                }

                const resultObject = {
                    subject: subject,
                    subjectAltName: subjectAltName,
                    issuer: issuer,
                    validFrom: validFrom,
                    validUntil: validUntil,
                    currentlyValid: currentlyValid,
                    currentTLSVersion: currentTLSVersion,
                    daysRemaining: Math.floor((validUntil - today) / (1000 * 60 * 60 *24))
                };

                resolve(resultObject);
                socket.destroy();

            });
            socket.on('error', (err) => {
                resolve({
                    currentlyValid: false,
                    error: err.code || err.message,
                    subject: null,
                    subjectAltName: null,
                    issuer: null,
                    validFrom: null,
                    validUntil: null,
                    currentTLSVersion: null,
                    daysRemaining: null
                });
            });
        });
    }
    catch (error)
    {
        throw error;
    }
}

module.exports = {sslCheck};