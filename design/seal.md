# Design: sealing documents with XAdES and ASiC-E

Status: levels B, T and LT implemented in `src/seal/`, with revocation by CRL and OCSP; not exported by the package yet, whose layout is proposed in [Packaging](#packaging).

## Purpose and scope

Seal any file (PDF, plain text, Markdown, any other file) so that its origin and integrity can be checked:

- by third parties, with their own tools, of which the reference is DSS (Digital Signature Service, the open source validator of the European Commission);
- by applications of our own, with this library.

The seal is a **detached XAdES baseline signature** (ETSI EN 319 132-1), packaged with the sealed files in an **ASiC-E container** (ETSI EN 319 162-1, extension `.asice`). The same method applies to every type of file, PDF included.

Out of scope:

- **PAdES**, the signature embedded in a PDF, which Adobe Reader displays. A PDF sealed in an ASiC-E container validates in DSS, but its seal is not visible in a PDF reader.
- **Level LTA**, which renews time-stamps over the long term. Level LT must be designed so that it does not prevent it.
- **Access to the network.** The library never calls a time-stamping authority, a CRL distribution point or an OCSP responder. It builds the requests and checks the answers; the caller sends the requests, with its own HTTP client.

In scope: levels B, T and LT. Revocation is part of the first version, since a third party validating with DSS needs revocation data at every level (see [Behaviour of DSS 6.5.1](#behaviour-of-dss-651)).

## Normative basis

| Document | Version | Clauses applied |
|---|---|---|
| ETSI EN 319 132-1, XAdES, building blocks and baseline signatures | V1.3.1 (2024-07) | structure of the signature (4.3, 4.4.2, 5.2), levels B-B, B-T and B-LT (5.3, 5.4, 5.5.1, 6.3, Table 2) |
| ETSI EN 319 162-1, ASiC, building blocks and baseline containers | V1.1.1 (2016-04) | layout of the container (clause 4.4.3, Table 5, Annex A) |
| ETSI TS 119 312, cryptographic suites | V2.1.1 (2026-06) | algorithms and key sizes |
| RFC 3161, time-stamp protocol (updated by RFC 5816) | not read in full | request (2.4.1), response and TSTInfo (2.4.2), certificate of the authority (2.3), its revocation (4) |
| RFC 5652, CMS | not read in full | the SignedData of the time-stamp token |
| RFC 2634 and RFC 5035, ESS | not read in full | the attributes signingCertificate and signingCertificateV2 of the token |
| RFC 5280, certificates and CRLs | not read in full | CRL (5), issuing distribution point (5.2.5), reason code (5.3.1), CRL distribution points (4.2.1.13), authority information access (4.2.2.1), times (4.1.2.5) |
| RFC 6960, OCSP | 2013-06 | request and response, authorized responders (4.2.2.2), archive cutoff (4.4.4) |
| RFC 5019, lightweight OCSP profile | 2007-09 | the SHA-1 CertID of the requests (2.1.1) |
| RFC 6931, XML security algorithm identifiers | not read in full | URIs of RSA-PSS (2.3.10) and ECDSA (2.3.6) |
| RFC 4055 and RFC 4050 | not read in full | the parameters of RSA-PSS; the value `r \|\| s` of ECDSA |
| OASIS ODF 1.2, part 3 | not read in full | `META-INF/manifest.xml`, relative URIs |

## What a seal is

### The container

```
contract.asice                       ZIP, names and comments in UTF-8
├── mimetype                         first entry, stored (method 0), no extra field:
│                                    application/vnd.etsi.asic-e+zip
├── contract.pdf                     the sealed files, outside META-INF
├── notes.md
└── META-INF/
    ├── manifest.xml                 ODF manifest: required by the baseline (Table 5)
    └── signatures001.xml            asic:XAdESSignatures holding one ds:Signature
```

- The `mimetype` entry is optional in the norm (4.4.3.2), but it lets a tool recognise the container from its first bytes: the library always writes it.
- `META-INF/manifest.xml` is "if present" in clause 4.4.3.2 item 5b, but "shall be present" in the baseline (Table 5): the library always writes it.
- Signature files are named `META-INF/*signatures*.xml`. Their root is `asic:XAdESSignatures`, namespace `http://uri.etsi.org/02918/v1.2.1#`.
- Other files of `META-INF` must not have "signature", "timestamp", "manifest" or "container.xml" in their name, and must not be needed for the validation.
- References to the sealed files are relative URIs, resolved against the root of the container, not against `META-INF` (Annex A.6). A reference outside the container is not allowed.

### The signature (level B-B)

```xml
<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S1">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="…"/>
      <ds:SignatureMethod Algorithm="…"/>
      <ds:Reference Id="R1" URI="contract.pdf">          <!-- one per sealed file, no Transforms -->
        <ds:DigestMethod Algorithm="…"/><ds:DigestValue>…</ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#S1-SP">
        <ds:Transforms><ds:Transform Algorithm="…"/></ds:Transforms>
        <ds:DigestMethod Algorithm="…"/><ds:DigestValue>…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>…</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>…</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    <ds:Object>
      <xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#S1">
        <xades:SignedProperties Id="S1-SP">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>2026-01-01T12:00:00Z</xades:SigningTime>
            <xades:SigningCertificateV2>
              <xades:Cert><xades:CertDigest>
                <ds:DigestMethod Algorithm="…"/><ds:DigestValue>…</ds:DigestValue>
              </xades:CertDigest></xades:Cert>
            </xades:SigningCertificateV2>
          </xades:SignedSignatureProperties>
          <xades:SignedDataObjectProperties>
            <xades:DataObjectFormat ObjectReference="#R1">
              <xades:MimeType>application/pdf</xades:MimeType>
            </xades:DataObjectFormat>
          </xades:SignedDataObjectProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</asic:XAdESSignatures>
```

The rules of the baseline this structure follows (EN 319 132-1):

- one `QualifyingProperties`, in one `ds:Object`, whose `Target` names the `Id` of `ds:Signature` (4.3.1, 6.3);
- a `ds:Reference` to `SignedProperties`, of type `http://uri.etsi.org/01903#SignedProperties` (4.4.2);
- `SigningTime`, in UTC (5.2.1, 6.3 h): the time the signer claims, not a proven one;
- `SigningCertificateV2` with the digest of the DER encoding of the signing certificate; no `Cert/@URI`, and no `IssuerSerialV2` (5.2.2, 6.3 i and j). `SigningCertificate` (version 1) is forbidden;
- one `DataObjectFormat` with a `MimeType` per sealed file, whose `ObjectReference` names the `Id` of its `ds:Reference` (5.2.4, 6.3 k);
- the signing certificate in `ds:KeyInfo/ds:X509Data/ds:X509Certificate` (6.3 a); the intermediate certificates should be added when the verifier cannot obtain them otherwise (6.3 b, c);
- no empty property container (4.3.1 to 4.3.6), and the XAdES namespace `v1.3.2`; of the `v1.4.1` namespace, only `TimeStampValidationData`, at level LT.

### Level B-T

One `xades:SignatureTimeStamp` in `UnsignedSignatureProperties`, holding one RFC 3161 time-stamp token in `EncapsulatedTimeStamp`, and its `ds:CanonicalizationMethod` (5.3, 4.5, 6.3 n). The time-stamp covers the `ds:SignatureValue` element, tags included, canonicalized (5.3). It must be made before the signing certificate expires or is revoked (6.3 o).

The library checks the token as a signature of its own before it embeds it, and again at verification: one signer, the signed attributes `contentType` (TSTInfo), `messageDigest` and the ESS `signingCertificate` (version 1 or 2) that binds the certificate of the authority, the extended key usage `timeStamping` of that certificate, alone and critical (RFC 3161, 2.3), the algorithms of the seals. Its `ds:CanonicalizationMethod` is required: clause 4.5 asks the new signatures for it, and gives no default.

### Level B-LT

The material needed to validate the signature is embedded, in `UnsignedSignatureProperties`, after `SignatureTimeStamp` (5.4, 5.5.1, Table 2), in this order:

- `xades141:TimeStampValidationData` (namespace `v1.4.1`), right after the time-stamp it serves (5.5.1.2): the certificates of the path of the time-stamping authority that the token does not hold, its trust anchor included (`CertificateValues`), and their CRLs (`RevocationValues`). `CertificateValues` and `RevocationValues` of the signature itself shall not hold the material of the time-stamps (5.4.2, item 5; 5.4.3, item 4);
- `xades:CertificateValues`: the certificates of the path of the signing certificate that `ds:KeyInfo` does not hold, its trust anchor included (5.4.2);
- `xades:RevocationValues`: a CRL (`CRLValues/EncapsulatedCRLValue`) or an OCSP response (`OCSPValues/EncapsulatedOCSPValue`) for the signing certificate and each CA certificate of its path, the trust anchor excepted (5.4.3). Only the data that told the status of a certificate are embedded: a CRL given besides an OCSP response that told it is left out;
- no duplicate of a certificate or of a revocation value (Table 2, q and v): a CRL the signer's path already embeds is not repeated for the time-stamping authority; `CompleteCertificateRefsV2` and `CompleteRevocationRefs` shall not be present (Table 2).

The revocation values are issued after the time of the time-stamp: they show that the certificates were not revoked at that time. Right after a time-stamp, a CA has not issued such a CRL yet: the extension to level LT waits for its next one.

## API

The seals are a branch of the package `@webcoder31/ezxmldsig`, next to the tokens (see [Packaging](#packaging)). Until that layout is in place, the functions below live in `src/seal/`, and the entry point of the package does not export them.

```ts
import { createSeal, timestampRequest, addSignatureTimestamp, validationDataRequests, addValidationData, verifySeal } from '@webcoder31/ezxmldsig/seal';

// Level B: seal files into an ASiC-E container.
const asice: Buffer = createSeal(
  [{ name: 'contract.pdf', content: pdfBytes }, { name: 'notes.md', content: mdBytes, mimeType: 'text/markdown' }],
  signKeyPath, signCertPath, signKeyPassword,
  { chain: [intermediateCertPath], signatureAlgorithm: RSA_PSS_SHA256, digestAlgorithm: SHA256, signingTime },
);

// Level T, without network access: the library builds the request and checks the response;
// the caller sends the request to the time-stamping authority of its choice.
const request: Buffer = timestampRequest(asice, SHA256);         // DER TimeStampReq (RFC 3161)
const response: Buffer = await post(tsaUrl, request);            // the caller's own HTTP client
const asiceT: Buffer = addSignatureTimestamp(asice, response, { tsaCertPath });

// Level LT, without network access either: the library lists what to fetch,
// the caller fetches it, the library checks it and embeds it.
const needs = validationDataRequests(asiceT, { caCertPath, tsaCertPath });
//   needs.crls: [{ certificate, issuer, urls }]            urls: the http(s) CRL distribution points of the certificate
//   needs.ocsp: [{ certificate, issuer, urls, request }]   request: DER OCSPRequest, urls from authority information access
const asiceLT: Buffer = addValidationData(asiceT, { caCertPath, tsaCertPath, crls: [crlBytes], ocspResponses: [ocspBytes] });

// Verification.
const seal = verifySeal(asiceLT, { caCertPath, tsaCertPath, expectedSubject });  // tsaCertPath: required for a time-stamped seal
// Below level LT, the revocation data come from the caller: verifySeal(asiceT, { …, crls, ocspResponses }).
// At level LT, the data of the caller are used besides those of the seal: a newer one can tell a revocation.
seal.isValid();            // structure, algorithms, digests, signature, trust, time-stamp, revocation
seal.getLevel();           // 'B', 'T' or 'LT'
seal.getSigningTime();     // the claimed time (SigningTime)
seal.getTimestampTime();   // the proven time (level T), or null
seal.getFiles();           // [{ name, mimeType }]: only the files the seal covers
seal.getError();           // why it is not valid
seal.getSigningCertificate(); // the X509Cert of the signer
seal.isRevocationChecked();   // false when verified with revocation: false
```

The API follows the conventions of `XMLDSigToken`: synchronous, files given as paths or contents (`PemSource`), trust given by `caCertPath`, `signerCertPath` and `expectedSubject`, an error message rather than an exception for an invalid seal, an exception for a misuse.

### Verification rules

- **Every file of the container outside `META-INF` must be covered** by a `ds:Reference`. A file the seal does not cover is an anomaly, not a silent extra: otherwise a third party could add a file to a sealed container and present it as sealed.
- **The date at which the certificates are checked:**
  - level T: the time of the time-stamp, which is proven; the certificate of the time-stamping authority is checked at the current date, at level LT too: only a time-stamp over the time-stamp (level LTA) would let it be checked at an earlier date;
  - level B: the current date. `SigningTime` is claimed by the signer and cannot be used to check a certificate: a holder of a leaked key could date a seal before the expiry of its certificate.
- **Revocation is checked by default**, for the signing certificate, the CA certificates of its path (the trust anchor excepted) and the certificate of the time-stamping authority. The data come from the seal (level LT) or from the caller (`crls`, `ocspResponses`). A certificate without revocation data makes the seal invalid, as it makes it indeterminate for DSS. `revocation: false` turns the check off, for applications of our own whose CA publishes no CRL: the result then says so (`isRevocationChecked()` false), so that a seal checked without revocation is never taken for one checked with it.
- **The date of the revocation data**: at level T and LT, a CRL or an OCSP response counts only if it was issued after the time of the time-stamp, and the certificate must not be revoked before that time; at level B, and for the time-stamping authority at level T, the data must be current (the next update of a CRL not passed). At level LT, the data of the time-stamping authority are embedded, and no longer current when the seal is verified: they count if issued after the time-stamp, as those of the signer. A CRL issued after the certificate expired proves nothing of it, a CA being free to drop the expired certificates from its CRLs, unless the CRL keeps them (`ExpiredCertsOnCRL`). The newest CRL tells the status; of two issued at the same second, the precision of their dates, the one that lists the certificate.
- **A revoked time-stamping authority** (RFC 3161, 4): a revocation after the time-stamp leaves its tokens valid only if the CRL gives a reason that is not a compromise of a key (`keyCompromise`, `cACompromise`, `aACompromise`); without a reason, every token of the authority is distrusted, whatever its date.
- **Level LT is self-sufficient**: the validation data a seal embeds must tell the status of every certificate by themselves, or the seal is invalid. CRLs and OCSP responses given by the caller are used besides them, so that a revocation published since is seen. `getLevel()` returns `'LT'` from the structure of the seal when it is verified with `revocation: false`.
- **The CRLs used** are complete and direct: a delta CRL, an indirect CRL, a CRL restricted to some reasons or a critical extension not known make the CRL unusable, and the caller who gave it gets an exception. A CRL restricted to end-entity or to CA certificates (issuing distribution point) covers those only.
- **CRLs and OCSP responses are signed**: their signature is verified, with the algorithm policy of the seals. A CRL is signed by the CA that issued the certificate. An OCSP response is signed by that CA, or by a responder it delegated (RFC 6960, 4.2.2.2): a certificate it issued directly, of extended key usage `id-kp-OCSPSigning`, valid when the response was produced. The delegated responder must carry `id-pkix-ocsp-nocheck` (4.2.2.2.1): the library does not check the revocation of responders. A response whose status is `unknown`, or about another certificate, tells nothing.
- **OCSP requests** identify the certificate by SHA-1 hashes of the name and of the key of its issuer, as the lightweight profile requires (RFC 5019, 2.1.1) and as responders expect: an identifier, not a signature. They have no nonce: the responses of a seal are kept, and the date rules above, not a nonce, tell whether a response counts. Responses with a CertID by SHA-256, SHA-384 or SHA-512 are accepted too. An OCSP response counts by the `thisUpdate` of its answer, as a CRL; the archive cutoff (4.4.4) plays the part of `ExpiredCertsOnCRL`.
- **The trust in the time-stamping authority** is declared by the verifier (`tsaCertPath`), as the trust in the signer is (`caCertPath`). A time-stamp of an authority the verifier does not trust makes the seal invalid, not a level B seal.
- The checks of the tokens apply: algorithm policy, canonicalization guards, no DOCTYPE, limited depth, one signature per signature file.

## Algorithms

TS 119 312 classifies RSA-PKCS#1 v1.5, the signature of the tokens, as a legacy mechanism, and recommends RSA-PSS and ECDSA on P-256 or P-384 (Table 2). RSA keys of 1 900 to less than 3 000 bits shall not be used to issue new certificates after 2026-12-31 (Table 6). The seals therefore:

- follow the type of the key: ECDSA for an EC key, RSA-PSS by default for an RSA key; RSA-PKCS#1 v1.5 stays available on request and accepted at verification, for existing certificates;
- accept ECDSA keys, which certificates of electronic seals on dedicated hardware often have; the XML signature value is `r || s`, not the DER encoding Node.js produces by default (`dsaEncoding: 'ieee-p1363'`);
- digest with SHA-256, SHA-384 or SHA-512; SHA-1 and MD5 are refused.

RSA-PSS has a cost for the PHP library to come: `openssl_sign()` and `openssl_verify()` take no padding parameter, in PHP 7.4 as in 8.3, so PHP cannot produce or check RSA-PSS with the OpenSSL extension alone. The PHP seals will need either the PSS encoding (RFC 8017, 9.1) written over raw RSA (`OPENSSL_NO_PADDING`), or a dependency such as phpseclib. ECDSA has no such cost.

## Reuse of ezxmldsig-js

| Need | Existing | Work |
|---|---|---|
| Canonicalization with its guards | `canonicalize()` (`src/c14n.ts`) | none |
| Guarded XML parsing | `loadXML()` (`src/xml.ts`) | none |
| Algorithm identifiers | `src/algorithms.ts` | add RSA-PSS and ECDSA (RFC 6931) |
| Certificates, chain of trust | `X509Cert.isTrustedBy()` (`src/x509.ts`) | check at a given date: an optional parameter, today `Date.now()` |
| DER | reader (`src/der.ts`) | an encoder, for the time-stamp request |
| Signature, its references and their verification | specific to tokens (`src/token.ts`) | new: several detached references, typed references, signed properties |
| ZIP | none | new: a writer, and a strict reader (see decisions) |
| RFC 3161 | none | new: request, response, token verification (a CMS signature) |
| CRL, OCSP | none | new: parsing, verification of their signature, OCSP request |

These parts are taken from ezxmldsig-js, not copied: `src/seal/` imports its modules `algorithms`, `c14n`, `der`, `encoding`, `material`, `x509` and `xml`; `token`, `xmlenc` and `options` are used by the tokens only. Those seven modules are the outline of the shared core (see [Packaging](#packaging)).

## Tests

- **Unit tests** of each property and rule above, with certificates generated for the tests: RSA 3072, RSA 2048 (legacy), ECDSA P-256.
- **Attack tests**, in the manner of the attack lab of the tokens: a file added to the container, a file replaced, a reference moved, a `SignedProperties` altered, a signing certificate swapped in `KeyInfo`, a time-stamp of another signature.
- **Validation by DSS**, which does not go through our code: DSS 6.5.1 is built from the official `Dockerfile` of `esig/dss-demonstrations` and runs locally, started with its configuration by `bin/dss start`; every seal produced by the tests is sent to `POST /services/rest/validation/validateSignature`. A test asserts the format reported (`XAdES-BASELINE-B`, `XAdES-BASELINE-T`, `XAdES-BASELINE-LT`, container `ASiC-E`), and that no integrity error is reported. The root CA of the tests is a trust anchor of DSS (see [Behaviour of DSS 6.5.1](#behaviour-of-dss-651)). The tests publish the CRLs of the test PKI where `bin/dss` serves them to DSS, at `pki.ezxmlseal.test`: the expected indication is `TOTAL_PASSED`, at every level. Every test file publishes the same CRLs, which revoke one certificate kept for that purpose: the files run at the same time, and none changes what another one validates.
- **Time-stamps, CRLs and OCSP responses** come from test issuers written apart from the library (`test/helpers/`), each field settable so that a test builds one fault, and from OpenSSL (`openssl ts`, `openssl ca`, `openssl ocsp`). No response of a public authority is recorded yet (see [Open points](#open-points)).

## Decisions

1. **One package per language**: the seals are a branch of `@webcoder31/ezxmldsig` (npm) and of `webcoder31/ezxmldsig` (Packagist), beside the tokens, both built on a core of the same package (see [Packaging](#packaging)). A seal is an XML signature, as a token is: the name covers both.
2. **ZIP: an implementation of our own**, with `node:zlib` (`deflateRawSync`, `inflateRawSync`, `crc32`), no dependency. The writer produces what ASiC-E needs: `mimetype` first and stored, the other entries deflated, UTF-8 names, no ZIP64. The reader is the part where a library would not help: it must refuse what makes a container ambiguous, which general ZIP libraries accept. It reads the central directory and checks each local header against it; it refuses duplicate names, names with `..`, an absolute path or a backslash, encryption, methods other than stored and deflate, ZIP64, data before the first entry or between entries, and an uncompressed size beyond a limit (`maxOutputLength`). It accepts data descriptors (flag 3), which DSS writes for every deflated entry.
3. **Canonicalization: exclusive** (`http://www.w3.org/2001/10/xml-exc-c14n#`), for `SignedInfo`, `SignedProperties` and the time-stamp: allowed by ASiC, written by DSS, and independent of the namespaces declared on `asic:XAdESSignatures`. C14N 1.0 and 1.1 are accepted at verification.
4. **Signature algorithm**: it follows the key, ECDSA for an EC key and RSA-PSS for an RSA key, RSA-PKCS#1 v1.5 on request (see [Algorithms](#algorithms)).
5. **Plain detached XAdES without a container**: not in the first version. The signature over detached references is the same; only the resolution of the references changes (a URL instead of a ZIP entry). It comes with the seal of online content, which needs its own design (how the verifier fetches the content, and what a reference to a URL proves).
6. **Revocation**: in the first version, at verification and in level LT (see [Level B-LT](#level-b-lt) and [Verification rules](#verification-rules)).

## Behaviour of DSS 6.5.1

Settled by tests against DSS 6.5.1, with containers that DSS built itself (its demonstration key, and our test signing key) and copies of them altered by hand.

- **`META-INF/manifest.xml` is required.** A container DSS built, from which only `manifest.xml` is removed, is rejected: `TOTAL_FAILED`, `FORMAT_FAILURE`, "The manifest file is absent!". DSS writes it with an entry for `/` (`application/vnd.etsi.asic-e+zip`) and one per sealed file, the path written as is (`manifest:full-path="notes d'été.md"`), with its media type.
- **File names in `ds:Reference/@URI`**: DSS percent-encodes the space only. `contrat final.pdf` becomes `contrat%20final.pdf`; `notes d'été.md` becomes `notes%20d'été.md`, the apostrophe and the accented letter left as they are. The ZIP entries are named in UTF-8, flag 11 of the general purpose bits set.
- **Namespaces**: XAdES `http://uri.etsi.org/01903/v1.3.2#` at levels B and T, root `asic:XAdESSignatures` in `http://uri.etsi.org/02918/v1.2.1#`. DSS canonicalizes `SignedInfo`, `SignedProperties` and the time-stamp with exclusive canonicalization (`http://www.w3.org/2001/10/xml-exc-c14n#`), and writes `IssuerSerialV2`, which the baseline says should not be included.
- **Seals of this library at level T**: `XAdES-BASELINE-T`, the time-stamp of type `SIGNATURE_TIMESTAMP`, its imprint found and intact, its signature valid, with tokens of the test authority of the library and of `openssl ts`; the root of the authority is a trust anchor of DSS as the root of the signer is.
- **Seals of this library** (level B), sent to DSS with the root CA of their tests as a trust anchor: every reference and the signed properties found and intact, the signature intact, with RSA-PSS (`http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1`), RSA PKCS#1 v1.5 and ECDSA (P-256, P-384), with SHA-256 and SHA-512 digests. DSS also resolves references whose every segment is percent-encoded (`notes%20d'%C3%A9t%C3%A9.md`, `docs/a%23b%25c.txt`), and accepts `SigningCertificateV2` without `IssuerSerialV2`. A file altered after sealing gives `TOTAL_FAILED`, `HASH_FAILURE`.
- **The message "Unable to build a certificate chain up to a trusted list!"** belongs to the qualification of the signature, which needs an EU trusted list, not to its validation: it remains with any trust anchor of our own.
- **`mimetype`**: written first, stored, no extra field. The other entries are deflated. The ZIP has no comment.
- **Media types**: DSS writes `application/pdf` for a `.pdf` file, and `application/octet-stream` for a `.md` file.
- **A file added to a sealed container** is not an error for DSS: the indication does not change, a warning says "Not all files are signed!", and the scope of the signature lists the sealed files only. The rule of this design is stricter: such a file makes the seal invalid.
- **A trust anchor of our own**: DSS imports as trusted every certificate of the keystore named by `trusted.source.keystore.type`, `.filename` and `.password` in a file `dss-custom.properties` of its class path (`DSSBeanConfig.trustedCertificateSource()`). With the root CA of the tests of this library in such a keystore, a container signed with the test signing key is no longer reported without a trust anchor.
- **Seals of this library at level LT**: `XAdES-BASELINE-LT`, `TOTAL_PASSED`, the three CRLs of the seal (intermediate, root, root of the time-stamping authority) read from it (origin `INPUT_DOCUMENT`), with RSA 3072 and P-256 signers. DSS also fetches the CRL of the root of the time-stamping authority from its distribution point (origin `EXTERNAL`), the CRL that tells the status of the authority, which the seal embeds too.
- **Seals of level LT whose CRLs DSS cannot reach** (a branch of the test PKI whose distribution points name `offline.ezxmlseal.test`, which does not resolve on the network of DSS): `TOTAL_PASSED` by the three CRLs of the seal alone (origin `INPUT_DOCUMENT`, none `EXTERNAL`), the CRLs current or past their next update. The same seal at level T is `INDETERMINATE`, "No revocation data found for the certificate!": level LT is what makes it valid for a third party without network.
- **OCSP responses embedded in a seal of level LT** (the offline branch, the signer by a response of its CA, the other certificates by CRLs; or the signer and the time-stamping authority by responses of their CAs, the intermediate by the CRL of the root): `TOTAL_PASSED`, by the three revocation data of the seal (origin `INPUT_DOCUMENT`).
- **The freshness of the revocation data is not checked by the default policy of DSS**: "Is the revocation information fresh for the certificate?" is `IGNORED`. A seal of level LT whose CRLs were issued before its time-stamp, built by hand, is `TOTAL_PASSED`, as long as the CRLs were issued within the validity of the certificates. This library is stricter: such CRLs do not tell the status at the time of the time-stamp, which a revocation between their issue and the time-stamp would change, and the seal is invalid.
- **With the CRLs of the test PKI served at `pki.ezxmlseal.test`**, the seals of the tests are `TOTAL_PASSED` at levels B and T; a signer listed in the CRL of the intermediate gives `INDETERMINATE`, `REVOKED_NO_POE`, "The certificate is revoked!". DSS keeps the CRLs it fetched in a cache until their next update, at most three hours by default (`cache.crl.max.next.update`): `bin/dss` brings it down to one second, so that a CRL published again is seen.
- **Revocation is required by the default policy of DSS, at levels B and T alike.** With the test root CA as a trust anchor, the container signed with the test signing key is `INDETERMINATE`, `CERTIFICATE_CHAIN_GENERAL_FAILURE`, "No revocation data found for the certificate!". A third party validating with DSS therefore needs to reach revocation data for the signing certificate: a CA whose certificates name a CRL distribution point or an OCSP responder that answers, or revocation data embedded in the seal (level LT).

## Packaging

Status: proposal, to be decided.

### One package, three branches

Each language has one package, `@webcoder31/ezxmldsig` on npm and `webcoder31/ezxmldsig` on Packagist, in one repository, `ezxmldsig-js` and `ezxmldsig-php`. The package has three branches:

- **core**: what the tokens and the seals share, certificates and chain of trust, DER, guarded XML parsing, canonicalization, algorithm identifiers, PEM sources;
- **token**: the signed and encrypted XML tokens;
- **seal**: the seals of files, XAdES in ASiC-E.

`token` and `seal` are siblings: each depends on `core`, neither on the other, and `core` on neither. A fix in `core` reaches both in one release, and nothing is published in between: a change of `core` is seen by `token` and `seal` as soon as it is written.

One package rather than three: the seals add no dependency to those of the tokens in Node.js (`@xmldom/xmldom`, and modules of Node.js: `node:crypto`, `node:zlib`); one release carries a fix to both; no version of a core is to be published before its users can take a change. What is lost is the independent versioning of the tokens and of the seals: see [Versions](#versions).

### What goes into each branch

| Module | Lines | Tokens | Seals | Branch |
|---|---|---|---|---|
| `der.ts`, DER reader and encoder | 242 | through `x509.ts` | CRL, OCSP, time-stamps | core |
| `x509.ts`, `X509Cert`, chain of trust, `matchesName` | 941 | yes | yes | core |
| `material.ts`, PEM sources | 83 | yes | yes | core |
| `xml.ts`, guarded parsing | 193 | yes | `loadXML` | core |
| `c14n.ts`, canonicalization with its guards | 36 | yes | yes | core |
| `algorithms.ts`, identifiers | 79 | yes | signature, digest and canonicalization identifiers | core: the identifiers of XML Signature, with RSA-PSS and ECDSA of `src/seal/algorithms.ts`; token: those of XML Encryption |
| `encoding.ts`, escaping and token formats | 96 | yes | `escapeText`, `escapeAttribute` | core: the two escaping functions; token: `phpBase64Decode`, `parseTokenDate`, `formatTokenDate`, `isXmlName` |
| `token.ts`, `options.ts`, `xmlenc.ts` | 2 253 | yes | no | token |
| `src/seal/` | 3 269 | no | yes | seal |

The time-stamps, the CRLs, OCSP and `pkix.ts` stay in `seal`: the tokens check neither revocation nor time-stamps. Should they one day, those modules move into `core` then, with boundaries drawn from that second use, not before. The policy of algorithms of the seals (`SIGNATURE_SCHEMES`, `MIN_RSA_BITS`) stays in `seal`, that of the tokens in `token`: they differ, the tokens signing with RSA PKCS#1 v1.5 for their interoperability with the PHP library.

The dependency `xpath` is used by `token` only, `xml-crypto` by `core` only, through an internal path (`xml-crypto/lib/utils.js`), hence its version pinned exactly; `@xmldom/xmldom` by the three branches.

### Layout

Node.js:

```
src/core/       algorithms.ts c14n.ts der.ts encoding.ts material.ts x509.ts xml.ts index.ts
src/token/      token.ts options.ts xmlenc.ts encoding.ts algorithms.ts index.ts
src/seal/       seal.ts verify.ts extend.ts validation.ts timestamp.ts crl.ts ocsp.ts revocation.ts pkix.ts zip.ts algorithms.ts index.ts
test/core/  test/token/  test/seal/
```

The package exports three subpaths, one per branch, and no root:

```ts
import { X509Cert, SHA256, type PemSource } from '@webcoder31/ezxmldsig/core';
import { XMLDSigToken } from '@webcoder31/ezxmldsig/token';
import { createSeal, verifySeal } from '@webcoder31/ezxmldsig/seal';
```

`core` exports its public names only: `X509Cert`, `NameFields`, `PemSource`, the algorithm identifiers. Its other functions, the DER reader, `loadXML`, `canonicalize`, `readPem`, are imported by `token` and `seal` inside the package, and are not reachable from outside: the field `exports` of `package.json` lists the three subpaths alone. They can change in any release.

PHP, by namespace, with PSR-4 (one directory per namespace):

```
src/core/       webcoder31\ezxmldsig\core     X509Cert, the policy of algorithms, canonicalization, the guards
src/token/      webcoder31\ezxmldsig\token    XMLDSigToken
src/seal/       webcoder31\ezxmldsig\seal     the seals, when they are written in PHP
```

In PHP, `core` is to be cut out of `XMLDSigToken.php`, where the policy of algorithms, the canonicalization, the guards against the attacks on XMLDSig and the loading of the trust anchors are mixed with the tokens. PHP has no equivalent of the field `exports`: the classes of `core` that are not meant for the applications are marked `@internal`.

### The boundaries, checked

The rule that `core` imports neither `token` nor `seal`, and that `token` and `seal` do not import each other, is checked by a test, not left to review: it reads the imports of every file of `src/` (the `use` statements in PHP) and fails on one that crosses a boundary.

### Versions

- **The move is a major version**, 2.0.0 in both languages: `XMLDSigToken` and `X509Cert` change of import path (Node.js) or of namespace (PHP). The CHANGELOG gives the old and the new name of each public symbol. No alias is kept: the libraries are barely distributed (no dependent package on Packagist), and the branches start clean.
- **The seals are experimental in 2.x**, until a review of their API: their changes may break in a minor version, which the README and the CHANGELOG say. The tokens and `core` follow semantic versioning. One version number carries both, the price of one package: a release of the seals is a release of the tokens too, with nothing changed for them.
- **When to split after all**: in PHP, the seals need RSA-PSS, which the OpenSSL extension cannot produce. If the PHP seals take a dependency for it (such as phpseclib) rather than an encoding of their own, or need a version of PHP above that of the tokens (7.4 today), every user of the tokens would bear it: the seals would then become a package of their own in PHP, depending on the PHP package for `core`.

### Order of the work

1. **Node.js, on the branch of the design**: the modules into `src/core/` and `src/token/`, `encoding.ts` and `algorithms.ts` split, the imports, `test/core/` and `test/token/`, the test of the boundaries, the three subpaths in `package.json`, the entry points of the documentation of the API (TypeDoc), the README and the CHANGELOG of 2.0.0. The whole suite passes, the interoperability with the PHP library included.
2. **The branch merged** into `main` of ezxmldsig-js, then 2.0.0 published.
3. **PHP**: `core` cut out of `XMLDSigToken.php`, the namespaces `core` and `token`, 2.0.0; the PHP seals later, in `seal`.

## Open points

- **The layout of the package**: the seals are not exported yet; the layout in three branches is proposed in [Packaging](#packaging), to be decided.
- **Public time-stamping authorities**: which ones answer without an account, and whether their certificates carry the revocation data level LT needs.
- **OCSP fetched by DSS**: the tests give DSS OCSP responses embedded in the seals only. `bin/dss` serves files, and an OCSP responder answers a POST: the certificates of the test PKI name one at `pki.ezxmlseal.test/ocsp`, which nothing answers yet.
