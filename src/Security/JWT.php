<?php

namespace Cleup\Guard\Security;

use DomainException;
use InvalidArgumentException;
use UnexpectedValueException;

class JWT
{
    private const ASN1_INTEGER = 0x02;
    private const ASN1_SEQUENCE = 0x10;
    private const ASN1_BIT_STRING = 0x03;

    /**
     * Default signing algorithm
     * 
     * @var string
     */
    private $algorithm = 'HS256';

    /**
     * Token expiration time in seconds
     * 
     * @var int|null
     */
    private $expiration = null;

    /**
     * Time leeway for token validation (in seconds)
     * 
     * @var int
     */
    private $leeway = 0;

    /**
     * Fixed timestamp for testing
     * 
     * @var int|null
     */
    private $timestamp = null;

    /**
     * The key or key array for signing/verification
     * 
     * @var mixed
     */
    private $keyOrKeyArray;

    /**
     * Supported algorithms
     * 
     * @var array<string, array<string, string>>
     */
    private static $supportedAlgs = [
        'ES384' => ['openssl', 'SHA384'],
        'ES256' => ['openssl', 'SHA256'],
        'ES256K' => ['openssl', 'SHA256'],
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'RS256' => ['openssl', 'SHA256'],
        'RS384' => ['openssl', 'SHA384'],
        'RS512' => ['openssl', 'SHA512'],
        'EdDSA' => ['sodium_crypto', 'EdDSA'],
    ];

    /**
     * Constructor
     * 
     * @param mixed $keyOrKeyArray The secret key or array of keys
     * 
     * @throws InvalidArgumentException If key is empty
     */
    public function __construct(
        #[\SensitiveParameter] $keyOrKeyArray
    ) {
        if (empty($keyOrKeyArray)) {
            throw new InvalidArgumentException('Key may not be empty');
        }

        $this->keyOrKeyArray = $keyOrKeyArray;
    }

    /**
     * Set signing algorithm
     * 
     * @param string $algorithm The signing algorithm (HS256, HS384, HS512, RS256, etc.)
     * @return self
     * 
     * @throws InvalidArgumentException If algorithm is not supported
     */
    public function algorithm(string $algorithm): self
    {
        if (!isset(self::$supportedAlgs[$algorithm])) {
            throw new InvalidArgumentException('Algorithm not supported: ' . $algorithm);
        }

        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * Set token expiration time
     * 
     * @param int $seconds Expiration time in seconds from now
     * @return self
     */
    public function expiresIn(int $seconds): self
    {
        $this->expiration = $seconds;
        return $this;
    }

    /**
     * Set token expiration at specific timestamp
     * 
     * @param int $timestamp Unix timestamp when token expires
     * @return self
     */
    public function expiresAt(int $timestamp): self
    {
        $this->expiration = $timestamp - time();
        return $this;
    }

    /**
     * Set time leeway for token validation
     * 
     * @param int $seconds Time leeway in seconds
     * @return self
     */
    public function leeway(int $seconds): self
    {
        $this->leeway = $seconds;
        return $this;
    }


    /**
     * Encode a PHP array into a JWT string
     * 
     * @param array $payload The payload data
     * @param string|null $keyId The key ID (kid)
     * @param array|null $headers Additional headers
     * @return string
     * 
     * @throws DomainException If algorithm is not supported or encoding fails
     */
    public function encode(
        array $payload,
        ?string $keyId = null,
        ?array $headers = null
    ): string {
        // Add expiration if set
        if ($this->expiration !== null) {
            $payload['exp'] = time() + $this->expiration;
        }

        // Build header
        $header = $this->buildHeader($this->algorithm, $keyId, $headers);

        // Create segments
        $segments = [
            $this->base64UrlEncode($this->jsonEncode($header)),
            $this->base64UrlEncode($this->jsonEncode($payload))
        ];

        // Create signing input and signature
        $signingInput = implode('.', $segments);
        $signature = $this->sign($signingInput, $this->algorithm);
        $segments[] = $this->base64UrlEncode($signature);

        return implode('.', $segments);
    }

    /**
     * Decode a JWT string into a PHP array
     * 
     * @param string $jwt The JWT string to decode
     * @param array|null $headers Reference to store headers
     * @return array
     * 
     * @throws InvalidArgumentException If JWT format is invalid
     * @throws DomainException If JWT has invalid encoding
     * @throws UnexpectedValueException If token validation fails
     */
    public function decode(string $jwt, ?array &$headers = null): array
    {
        $timestamp = $this->timestamp ?? time();

        // Split JWT into segments
        $segments = explode('.', $jwt);
        if (count($segments) !== 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        list($headb64, $bodyb64, $cryptob64) = $segments;

        // Decode and validate header
        $header = $this->decodeHeader($headb64);
        if ($headers !== null) {
            $headers = $header;
        }

        // Decode and validate payload
        $payload = $this->decodePayload($bodyb64);

        // Validate token timestamps
        $this->validateTokenTimestamps($payload, $timestamp);

        // Verify signature
        $this->verifySignature($header, $headb64, $bodyb64, $cryptob64);

        return $payload;
    }

    /**
     * Validate a JWT without throwing exceptions
     * 
     * @param string $jwt The JWT string to validate
     * @return bool
     */
    public function validate(string $jwt): bool
    {
        try {
            $this->decode($jwt);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Decode and validate JWT header
     * 
     * @param string $headb64 Base64Url encoded header
     * @return array
     * 
     * @throws UnexpectedValueException If header encoding is invalid
     */
    private function decodeHeader(string $headb64): array
    {
        $headerRaw = $this->base64UrlDecode($headb64);
        $header = $this->jsonDecode($headerRaw);

        if ($header === null) {
            throw new UnexpectedValueException('Invalid header encoding');
        }

        if (empty($header['alg'] ?? '')) {
            throw new UnexpectedValueException('Empty algorithm');
        }

        if (empty(self::$supportedAlgs[$header['alg']])) {
            throw new UnexpectedValueException('Algorithm not supported: ' . $header['alg']);
        }

        return $header;
    }

    /**
     * Decode and validate JWT payload
     * 
     * @param string $bodyb64 Base64Url encoded payload
     * @return array
     * 
     * @throws UnexpectedValueException If payload encoding is invalid
     */
    private function decodePayload(string $bodyb64): array
    {
        $payloadRaw = $this->base64UrlDecode($bodyb64);
        $payload = $this->jsonDecode($payloadRaw);

        if ($payload === null) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }

        if (!is_array($payload)) {
            $payload = (array) $payload;
        }

        return $payload;
    }

    /**
     * Validate token timestamps
     * 
     * @param array $payload The decoded payload
     * @param int $timestamp Current timestamp
     * 
     * @throws UnexpectedValueException If token timestamps are invalid
     */
    private function validateTokenTimestamps(array $payload, int $timestamp): void
    {
        // Validate numeric claims
        $this->validateNumericClaim($payload, 'iat');
        $this->validateNumericClaim($payload, 'nbf');
        $this->validateNumericClaim($payload, 'exp');

        // Check "not before" time
        if (isset($payload['nbf']) && floor($payload['nbf']) > ($timestamp + $this->leeway)) {
            throw new UnexpectedValueException(
                'Cannot handle token with nbf prior to ' . date('c', (int) floor($payload['nbf']))
            );
        }

        // Check "issued at" time (if nbf is not set)
        if (!isset($payload['nbf']) && isset($payload['iat']) && floor($payload['iat']) > ($timestamp + $this->leeway)) {
            throw new UnexpectedValueException(
                'Cannot handle token with iat prior to ' . date('c', (int) floor($payload['iat']))
            );
        }

        // Check expiration time
        if (isset($payload['exp']) && ($timestamp - $this->leeway) >= $payload['exp']) {
            throw new UnexpectedValueException('Expired token');
        }
    }

    /**
     * Validate that a claim is numeric if it exists
     * 
     * @param array $payload The payload
     * @param string $claim The claim name
     * 
     * @throws UnexpectedValueException If claim exists and is not numeric
     */
    private function validateNumericClaim(array $payload, string $claim): void
    {
        if (isset($payload[$claim]) && !is_numeric($payload[$claim])) {
            throw new UnexpectedValueException("Payload {$claim} must be a number");
        }
    }

    /**
     * Verify JWT signature
     * 
     * @param array $header The decoded header
     * @param string $headb64 Base64Url encoded header
     * @param string $bodyb64 Base64Url encoded body
     * @param string $cryptob64 Base64Url encoded signature
     * 
     * @throws UnexpectedValueException If signature verification fails
     */
    private function verifySignature(
        array $header,
        string $headb64,
        string $bodyb64,
        string $cryptob64
    ): void {
        $sig = $this->base64UrlDecode($cryptob64);
        $alg = $header['alg'];

        // Convert ECDSA signatures if needed
        if (in_array($alg, ['ES256', 'ES256K', 'ES384'], true)) {
            $sig = $this->signatureToDER($sig);
        }

        $msg = "{$headb64}.{$bodyb64}";

        if (!$this->verify($msg, $sig, $alg)) {
            throw new UnexpectedValueException('Signature verification failed');
        }
    }

    /**
     * Build JWT header
     * 
     * @param string $alg The algorithm
     * @param string|null $keyId The key ID
     * @param array|null $headers Additional headers
     * @return array
     */
    private function buildHeader(string $alg, ?string $keyId = null, ?array $headers = null): array
    {
        $header = ['typ' => 'JWT', 'alg' => $alg];

        if ($headers !== null) {
            $header = array_merge($header, $headers);
        }

        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }

        return $header;
    }

    /**
     * Create signature for message
     * 
     * @param string $msg The message to sign
     * @param string $alg The algorithm to use
     * @return string
     * 
     * @throws DomainException If algorithm is not supported or signing fails
     */
    private function sign(string $msg, string $alg): string
    {
        if (empty(self::$supportedAlgs[$alg])) {
            throw new DomainException('Algorithm not supported: ' . $alg);
        }

        list($function, $algorithm) = self::$supportedAlgs[$alg];
        $key = $this->getSigningKey();

        switch ($function) {
            case 'hash_hmac':
                if (!is_string($key)) {
                    throw new InvalidArgumentException('key must be a string when using hmac');
                }
                return hash_hmac($algorithm, $msg, $key, true);

            case 'openssl':
                $success = false;
                $signature = '';

                // Try to use key directly
                $success = openssl_sign($msg, $signature, $key, $algorithm);

                if (!$success) {
                    // Try to get private key
                    $privateKey = openssl_pkey_get_private($key);
                    if ($privateKey === false) {
                        throw new DomainException('OpenSSL unable to validate key');
                    }
                    $success = openssl_sign($msg, $signature, $privateKey, $algorithm);
                }

                if (!$success) {
                    throw new DomainException('OpenSSL unable to sign data');
                }

                if ($alg === 'ES256' || $alg === 'ES256K') {
                    $signature = $this->signatureFromDER($signature, 256);
                } elseif ($alg === 'ES384') {
                    $signature = $this->signatureFromDER($signature, 384);
                }
                return $signature;

            case 'sodium_crypto':
                if (!function_exists('sodium_crypto_sign_detached')) {
                    throw new DomainException('libsodium is not available');
                }
                if (!is_string($key)) {
                    throw new InvalidArgumentException('key must be a string when using EdDSA');
                }

                try {
                    // Clean up the key - remove any whitespace and decode
                    $key = trim($key);
                    $lines = array_filter(explode("\n", $key));

                    if (count($lines) > 1) {
                        // Likely PEM format, use the last non-empty line
                        $key = base64_decode(trim((string) end($lines)));
                    } else {
                        // Might already be raw key or base64 encoded
                        $key = preg_match('/^[a-zA-Z0-9\/+]+={0,2}$/', $key)
                            ? base64_decode($key)
                            : $key;
                    }

                    if (strlen($key) === 0) {
                        throw new DomainException('Key cannot be empty string');
                    }
                    return sodium_crypto_sign_detached($msg, $key);
                } catch (\Exception $e) {
                    throw new DomainException($e->getMessage(), 0, $e);
                }
        }

        throw new DomainException('Algorithm not supported: ' . $alg);
    }

    /**
     * Verify signature for message
     * 
     * @param string $msg The message
     * @param string $signature The signature
     * @param string $alg The algorithm
     * @return bool
     * 
     * @throws DomainException If algorithm is not supported or verification fails
     */
    private function verify(string $msg, string $signature, string $alg): bool
    {
        if (empty(self::$supportedAlgs[$alg])) {
            throw new DomainException('Algorithm not supported: ' . $alg);
        }

        list($function, $algorithm) = self::$supportedAlgs[$alg];
        $keyMaterial = $this->getVerificationKey();

        switch ($function) {
            case 'openssl':
                $success = openssl_verify($msg, $signature, $keyMaterial, $algorithm);
                if ($success === 1) {
                    return true;
                }
                if ($success === 0) {
                    return false;
                }
                throw new DomainException('OpenSSL error: ' . openssl_error_string());

            case 'sodium_crypto':
                if (!function_exists('sodium_crypto_sign_verify_detached')) {
                    throw new DomainException('libsodium is not available');
                }
                if (!is_string($keyMaterial)) {
                    throw new InvalidArgumentException('key must be a string when using EdDSA');
                }

                try {
                    // Clean up the key
                    $keyMaterial = trim($keyMaterial);
                    $lines = array_filter(explode("\n", $keyMaterial));

                    if (count($lines) > 1) {
                        $key = base64_decode(trim((string) end($lines)));
                    } else {
                        $key = preg_match('/^[a-zA-Z0-9\/+]+={0,2}$/', $keyMaterial)
                            ? base64_decode($keyMaterial)
                            : $keyMaterial;
                    }

                    if (strlen($key) === 0) {
                        throw new DomainException('Key cannot be empty string');
                    }
                    if (strlen($signature) === 0) {
                        throw new DomainException('Signature cannot be empty string');
                    }
                    return sodium_crypto_sign_verify_detached($signature, $msg, $key);
                } catch (\Exception $e) {
                    throw new DomainException($e->getMessage(), 0, $e);
                }

            case 'hash_hmac':
            default:
                if (!is_string($keyMaterial)) {
                    throw new InvalidArgumentException('key must be a string when using hmac');
                }
                $hash = hash_hmac($algorithm, $msg, $keyMaterial, true);
                return $this->constantTimeEquals($hash, $signature);
        }
    }

    /**
     * Get signing key
     * 
     * @return mixed
     */
    private function getSigningKey()
    {
        return $this->keyOrKeyArray;
    }

    /**
     * Get verification key
     * 
     * @return mixed
     */
    private function getVerificationKey()
    {
        return $this->keyOrKeyArray;
    }

    /**
     * Decode a JSON string
     * 
     * @param string $input JSON string
     * @return mixed
     * 
     * @throws DomainException If JSON is invalid
     */
    private function jsonDecode(string $input)
    {
        $obj = json_decode($input, true, 512, JSON_BIGINT_AS_STRING);

        if ($errno = json_last_error()) {
            $this->handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null' && $input !== '[]') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * Encode array to JSON string
     * 
     * @param array $input PHP array
     * @return string
     * 
     * @throws DomainException If encoding fails
     */
    private function jsonEncode(array $input): string
    {
        $json = json_encode($input, JSON_UNESCAPED_SLASHES);
        if ($errno = json_last_error()) {
            $this->handleJsonError($errno);
        } elseif ($json === false) {
            throw new DomainException('Provided object could not be encoded to valid JSON');
        }
        return $json;
    }

    /**
     * Decode Base64Url string
     * 
     * @param string $input Base64Url encoded string
     * @return string
     */
    private function base64UrlDecode(string $input): string
    {
        $decoded = base64_decode($this->convertBase64UrlToBase64($input), true);
        if ($decoded === false) {
            throw new InvalidArgumentException('Invalid base64 string');
        }
        return $decoded;
    }

    /**
     * Convert Base64Url to Base64
     * 
     * @param string $input Base64Url string
     * @return string
     */
    private function convertBase64UrlToBase64(string $input): string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return strtr($input, '-_', '+/');
    }

    /**
     * Encode string to Base64Url
     * 
     * @param string $input The string to encode
     * @return string
     */
    private function base64UrlEncode(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Compare strings in constant time
     * 
     * @param string $left First string
     * @param string $right Second string
     * @return bool
     */
    private function constantTimeEquals(string $left, string $right): bool
    {
        if (function_exists('hash_equals')) {
            return hash_equals($left, $right);
        }

        $len = min(strlen($left), strlen($right));
        $status = 0;

        for ($i = 0; $i < $len; $i++) {
            $status |= (ord($left[$i]) ^ ord($right[$i]));
        }
        $status |= (strlen($left) ^ strlen($right));

        return ($status === 0);
    }

    /**
     * Handle JSON error
     * 
     * @param int $errno JSON error code
     * 
     * @throws DomainException With error message
     */
    private function handleJsonError(int $errno): void
    {
        $messages = [
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters'
        ];
        throw new DomainException($messages[$errno] ?? 'Unknown JSON error: ' . $errno);
    }

    /**
     * Convert ECDSA signature to DER format
     * 
     * @param string $sig The ECDSA signature
     * @return string
     */
    private function signatureToDER(string $sig): string
    {
        $length = max(1, (int) (strlen($sig) / 2));
        list($r, $s) = str_split($sig, $length);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        if (ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return $this->encodeDER(
            self::ASN1_SEQUENCE,
            $this->encodeDER(self::ASN1_INTEGER, $r) .
                $this->encodeDER(self::ASN1_INTEGER, $s)
        );
    }

    /**
     * Encode value to DER format
     * 
     * @param int $type DER type
     * @param string $value The value to encode
     * @return string
     */
    private function encodeDER(int $type, string $value): string
    {
        $tag_header = 0;
        if ($type === self::ASN1_SEQUENCE) {
            $tag_header |= 0x20;
        }

        $der = chr($tag_header | $type);
        $der .= chr(strlen($value));

        return $der . $value;
    }

    /**
     * Convert signature from DER format
     * 
     * @param string $der DER encoded signature
     * @param int $keySize Key size in bits
     * @return string
     */
    private function signatureFromDER(string $der, int $keySize): string
    {
        list($offset, $_) = $this->readDER($der);
        list($offset, $r) = $this->readDER($der, $offset);
        list($offset, $s) = $this->readDER($der, $offset);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        $r = str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * Read DER encoded data
     * 
     * @param string $der DER encoded data
     * @param int $offset Starting offset
     * @return array
     */
    private function readDER(string $der, int $offset = 0): array
    {
        $pos = $offset;
        $size = strlen($der);
        $constructed = (ord($der[$pos]) >> 5) & 0x01;
        $type = ord($der[$pos++]) & 0x1f;

        $len = ord($der[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = ($len << 8) | ord($der[$pos++]);
            }
        }

        if ($type === self::ASN1_BIT_STRING) {
            $pos++;
            $data = substr($der, $pos, $len - 1);
            $pos += $len - 1;
        } elseif (!$constructed) {
            $data = substr($der, $pos, $len);
            $pos += $len;
        } else {
            $data = null;
        }

        return [$pos, $data];
    }
}
