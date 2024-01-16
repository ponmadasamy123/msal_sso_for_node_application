"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var request_1 = require("request");
const jsonwebtoken_1 = require("jsonwebtoken");
/** -Token Verification Function */
var convertCertificateToBeOpenSSLCompatible = function (cert) {
    var beginCert = '-----BEGIN CERTIFICATE-----';
    var endCert = '-----END CERTIFICATE-----';
    cert = cert.replace('\n', '');
    cert = cert.replace(beginCert, '');
    cert = cert.replace(endCert, '');
    var result = beginCert;
    while (cert.length > 0) {
        if (cert.length > 64) {
            result += '\n' + cert.substring(0, 64);
            cert = cert.substring(64, cert.length);
        }
        else {
            result += '\n' + cert;
            cert = '';
        }
    }
    if (result[result.length] != '\n')
        result += '\n';
    result += endCert + '\n';
    return result;
};
var verifyToken = function (token) {
    return new Promise(function (accept, reject) {
        // Extract token info without verify
        var decodedToken = jsonwebtoken_1.decode(token, { complete: true });
        if (decodedToken && decodedToken.payload && decodedToken.header) {
            // Email will be used to get user info
            // const email = decodedToken.payload.email;
            var tenantId = decodedToken.payload.tid;
            var kid_1 = decodedToken.header.kid;
            var tenantOpenIdconfig = {
                url: 'https://login.microsoftonline.com/' +
                    tenantId +
                    '/v2.0/.well-known/openid-configuration',
                json: true,
            };
            // Loading the open-id configuration for a specific AAD tenant from a well known application.
            request_1.get(tenantOpenIdconfig, function (error, response, result) {
                if (error) {
                    reject(error);
                }
                else {
                    var jwks_uri = result.jwks_uri;
                    var jwtSigningKeyRequestOptions = {
                        url: jwks_uri,
                        json: true,
                    };
                    // Download the signing certificates which is the public portion of the keys used to sign the JWT token
                    request_1.get(jwtSigningKeyRequestOptions, function (error, response, result) {
                        if (error) {
                            reject(error);
                        }
                        else {
                            var certificates_1 = [];
                            // Use KID to locate the public key and store the certificate chain.
                            result.keys.find(function (publicKey) {
                                if (publicKey.kid === kid_1) {
                                    publicKey.x5c.forEach(function (certificate) {
                                        certificates_1.push(convertCertificateToBeOpenSSLCompatible(certificate));
                                    });
                                }
                            });
                            var options_1 = {
                                algorithms: ['RS256'],
                            };
                            certificates_1.every(function (certificate) {
                                // verify the token
                                try {
                                    // verify the token
                                    jsonwebtoken_1.default.verify(token, certificate, options_1);
                                    // abort the enumeration
                                    return false;
                                }
                                catch (error) {
                                    // check if we should try the next certificate
                                    if (error.message === 'invalid signature') {
                                        return true;
                                    }
                                    else {
                                        return false;
                                    }
                                }
                            });
                        }
                    });
                }
            });
        }
        else {
            reject(new Error('Not a valid AAD token'));
        }
    });
};
exports.default = verifyToken;
/** Azure Token Verification*/
