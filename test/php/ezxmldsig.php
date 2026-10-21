<?php
/**
 * Runs requests against the PHP library ezxmldsig (see bin/php-ezxmldsig).
 *
 * Reads a JSON array of requests on stdin and writes a JSON array of results,
 * one per request, on stdout. A request is an object whose "command" is:
 *
 * - "create": creates a token, with createXMLToken(), or with
 *   createSecureXMLToken() when "cryptCert" is given. Fields: "data",
 *   "signKey", "signCert", "signKeyPassword", "cryptCert", "cryptKey",
 *   "cryptKeyPassword", "options". Result: the analysis below, of the
 *   created token.
 *
 * - "analyze": analyzes "xml" with analyzeXMLToken(), or with
 *   analyzeSecureXMLToken() when "cryptKey" is given. Fields: "xml",
 *   "cryptKey", "cryptKeyPassword", "options", and "ttl" for isOutOfDate()
 *   (default: 60).
 *
 * - "cert": reads the certificate "cert" (a path) with X509Cert. Fields:
 *   "trustedBy", a list of lists of CA certificate paths, and "validCA", a
 *   list of CA certificate paths. Result: what X509Cert returns, with
 *   isTrustedBy() for each list of "trustedBy" and isValidCA() for each
 *   certificate of "validCA", in the same order.
 *
 * - "forge": alters the token "xml" with the class Forge of the attack lab
 *   of the PHP library demo, which works with xmlseclibs, not with
 *   XMLDSigToken. Field: "steps", a list of {"op": "redigest"} (digest of
 *   ds:Object computed again), {"op": "resign", "key", "password", "cert"}
 *   (ds:SignedInfo signed again, and the certificate replaced),
 *   {"op": "replaceCertificate", "cert"}, {"op": "encrypt", "cert",
 *   "cipher", "keyTransport", "type"} (the node Token, or the content of
 *   ds:Object for the type Content, encrypted with xmlseclibs for the
 *   certificate, with any algorithm it knows, RSA 1.5 included) or
 *   {"op": "encryptPlaintext", "cert", "plaintext"} (the encrypted session
 *   key and data replaced by a new AES-256-GCM key, RSA-OAEP encrypted for
 *   the certificate, and the given plaintext). Result: {"xml": the altered
 *   token}.
 *
 * - "constants": the constants of XMLDSigToken (no field). Result: an
 *   object of their names and values.
 *
 * Token data that are not UTF-8 text are given as {"bytes": base64}.
 *
 * The algorithm options are given by their URIs, the values of the
 * constants of XMLDSigToken. The result of an analysis holds what the
 * accessors of the token return; an exception or an error thrown by the
 * library gives {"exception": message, "class": its class} instead.
 */

require '/ezxmldsig/vendor/autoload.php';
require '/ezxmldsig/demo/src/Forge.php';

use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use webcoder31\ezxmldsig\Demo\Forge;
use webcoder31\ezxmldsig\X509Cert;
use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * Gives the values of token data that are not UTF-8 text as
 * {"bytes": base64}, which JSON can hold.
 */
function jsonData($data)
{
    if (is_array($data))
    {
        return array_map('jsonData', $data);
    }
    return is_string($data) && !mb_check_encoding($data, 'UTF-8') ? ['bytes' => base64_encode($data)] : $data;
}

/**
 * Returns what the accessors of a token return.
 */
function describe(XMLDSigToken $token, $ttl)
{
    return [
        'xml'              => $token->getXML(),
        'isSignatureValid' => $token->isSignatureValid(),
        'isDigestValueOk'  => $token->isDigestValueOk(),
        'isSignatureValueOk' => $token->isSignatureValueOk(),
        'isCertTrusted'    => $token->isCertTrusted(),
        'isDataEncrypted'  => $token->isDataEncrypted(),
        'isOutOfDate'      => $token->isOutOfDate($ttl),
        'error'            => $token->getError(),
        'anomalies'        => $token->getAnomalies(),
        'data'             => jsonData($token->getData()),
        'timestamp'        => $token->getTimestamp(),
        'tokenId'          => $token->getTokenId(),
        'audience'         => $token->getAudience(),
        'expiry'           => $token->getExpiry(),
        'certDN'           => $token->getCertDN(),
        'certSubject'      => $token->getCertSubject(),
        'certIssuer'       => $token->getCertIssuer(),
        'certValidFrom'    => $token->getCertValidFrom(),
        'certValidTo'      => $token->getCertValidTo(),
    ];
}

/**
 * Runs one request.
 */
function run(array $request)
{
    $options = $request['options'] ?? [];
    $ttl = $request['ttl'] ?? XMLDSigToken::TOKEN_DEFAULT_TTL;

    switch ($request['command'] ?? null)
    {
        case 'create':
            $token = isset($request['cryptCert'])
                ? XMLDSigToken::createSecureXMLToken(
                    $request['data'],
                    $request['signKey'],
                    $request['signCert'],
                    $request['cryptKey'] ?? null,
                    $request['cryptCert'],
                    $request['signKeyPassword'] ?? null,
                    $request['cryptKeyPassword'] ?? null,
                    $options
                )
                : XMLDSigToken::createXMLToken(
                    $request['data'],
                    $request['signKey'],
                    $request['signCert'],
                    $request['signKeyPassword'] ?? null,
                    $options
                );
            return describe($token, $ttl);

        case 'analyze':
            $token = isset($request['cryptKey'])
                ? XMLDSigToken::analyzeSecureXMLToken(
                    $request['xml'],
                    $request['cryptKey'],
                    $request['cryptKeyPassword'] ?? null,
                    $options
                )
                : XMLDSigToken::analyzeXMLToken($request['xml'], $options);
            return describe($token, $ttl);

        case 'cert':
            $cert = new X509Cert(file_get_contents($request['cert']));
            return [
                'fingerprint' => $cert->getFingerprint(),
                'subject'     => $cert->getSubject(),
                'issuer'      => $cert->getIssuer(),
                'dn'          => $cert->getDN(),
                'validFrom'   => $cert->getValidFrom(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT),
                'validTo'     => $cert->getValidTo(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT),
                'isOutOfDate' => $cert->isOutOfDate(),
                'canSign'     => $cert->canSign(),
                'der'         => base64_encode(X509Cert::pemToDer(file_get_contents($request['cert']))),
                'trustedBy'   => array_map(function ($paths) use ($cert) {
                    return $cert->isTrustedBy($paths);
                }, $request['trustedBy'] ?? []),
                'validCA'     => array_map(function ($path) use ($cert) {
                    return $cert->isValidCA(file_get_contents($path));
                }, $request['validCA'] ?? []),
            ];

        case 'forge':
            $forge = new Forge($request['xml']);
            foreach ($request['steps'] as $step)
            {
                switch ($step['op'])
                {
                    case 'redigest':
                        $forge->redigest();
                        break;
                    case 'resign':
                        $forge->resign($step['key'], $step['password'] ?? null, $step['cert']);
                        break;
                    case 'replaceCertificate':
                        $forge->replaceCertificate($step['cert']);
                        break;
                    case 'encrypt':
                        $object = $forge->node('/ds:Signature/ds:Object');
                        $sessionKey = new XMLSecurityKey($step['cipher']);
                        $sessionKey->generateSessionKey();
                        $publicKey = new XMLSecurityKey($step['keyTransport'], ['type' => 'public']);
                        $publicKey->loadKey($step['cert'], true, true);
                        $enc = new XMLSecEnc();
                        $enc->encryptKey($publicKey, $sessionKey);
                        $type = 'Content' === $step['type'] ? XMLSecEnc::Content : XMLSecEnc::Element;
                        $enc->setNode(XMLSecEnc::Element === $type ? $object->firstChild : $object);
                        $enc->type = $type;
                        $enc->encryptNode($sessionKey);
                        break;
                    case 'encryptPlaintext':
                        $sessionKey = new XMLSecurityKey(XMLSecurityKey::AES256_GCM);
                        $sessionKey->generateSessionKey();
                        openssl_public_encrypt($sessionKey->key, $encryptedKey, openssl_pkey_get_public(file_get_contents($step['cert'])), OPENSSL_PKCS1_OAEP_PADDING);
                        $forge->node('/ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue')->nodeValue = base64_encode($encryptedKey);
                        $forge->node('/ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue')->nodeValue = base64_encode($sessionKey->encryptData($step['plaintext']));
                        break;
                    default:
                        throw new Exception("Unknown forge step!");
                }
            }
            return ['xml' => $forge->xml()];

        case 'constants':
            return (new ReflectionClass(XMLDSigToken::class))->getConstants();

        default:
            throw new Exception("Unknown command!");
    }
}

$requests = json_decode(stream_get_contents(STDIN), true);
if (!is_array($requests))
{
    fwrite(STDERR, "The requests must be a JSON array.\n");
    exit(1);
}

$results = [];
foreach ($requests as $request)
{
    try
    {
        $results[] = run($request);
    }
    catch (Throwable $e)
    {
        $results[] = ['exception' => $e->getMessage(), 'class' => get_class($e)];
    }
}

echo json_encode($results, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
