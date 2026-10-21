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
 * - "constants": the constants of XMLDSigToken (no field). Result: an
 *   object of their names and values.
 *
 * The algorithm options are given by their URIs, the values of the
 * constants of XMLDSigToken. The result of an analysis holds what the
 * accessors of the token return; an exception thrown by the library gives
 * {"exception": message} instead.
 */

require '/ezxmldsig/vendor/autoload.php';

use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * Returns what the accessors of a token return.
 */
function describe(XMLDSigToken $token, $ttl)
{
    return [
        'xml'              => $token->getXML(),
        'isSignatureValid' => $token->isSignatureValid(),
        'isCertTrusted'    => $token->isCertTrusted(),
        'isDataEncrypted'  => $token->isDataEncrypted(),
        'isOutOfDate'      => $token->isOutOfDate($ttl),
        'error'            => $token->getError(),
        'anomalies'        => $token->getAnomalies(),
        'data'             => $token->getData(),
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
    catch (Exception $e)
    {
        $results[] = ['exception' => $e->getMessage()];
    }
}

echo json_encode($results, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
