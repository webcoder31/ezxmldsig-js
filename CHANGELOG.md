# Changelog

## 1.0.1

No change to the library: its code is that of 1.0.0.

- The package is published by the workflow of the repository through npm trusted publishing (OpenID Connect), without an npm token. Its provenance still names the workflow and the commit it was built from.
- The README describes how a version is released (section "Releasing a version").

## 1.0.0

First version: the Node.js counterpart of the PHP library ezxmldsig 1.2.0, which creates and verifies the same XML tokens.

- `XMLDSigToken` creates signed tokens (`createXMLToken()`) and signed tokens whose data are encrypted (`createSecureXMLToken()`), and analyzes them (`analyzeXMLToken()`, `analyzeSecureXMLToken()`), with the options, the checks, the order of the checks and the error messages of the PHP library: trust anchor required, data read from the signed content only, algorithms checked, RSA 1.5 refused and CBC only accepted when declared, decryption only after verification and with a single error for every failure that depends on the encrypted content, audience and expiry, document type declarations refused before parsing.
- `X509Cert` reads X.509 certificates (subject, issuer, Distinguished Name in the format of the PHP library, validity dates, fingerprint) and verifies their chain up to trusted CA certificates, with the rules OpenSSL applies for the PHP library.
- Keys and certificates are given by path or by PEM content. The API is synchronous.
- The tokens are interoperable both ways with the PHP library 1.2.0, under PHP 7.4 and 8.3, and with xml-crypto and xml-encryption; the tests check it, and replay the attack lab of the PHP library demo.
- Differences with the PHP library 1.2.0: keys that are not RSA are refused; values that are not in base64 are written as text, `&` included; certificates dated 2050 or later are read; certification authorities with name constraints are refused. See the README, "Differences with the PHP library".
