<?php

namespace Cleup\Guard\Security;

/**
 * Advanced Encryption class for cryptographic operations
 * Provides UUID generation, encryption/decryption, and security utilities
 */
class Encryption
{
    private const UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';
    private const UUID_V4_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    private static $cipherMethods = [
        'AES-256-GCM',
        'AES-256-CBC',
        'AES-128-GCM',
        'AES-128-CBC'
    ];

    /**
     * Generates a version 4 (random) UUID
     * 
     * @return string|null Generated UUID or null on failure
     */
    public static function generateUuid(): ?string
    {
        try {
            $data = random_bytes(16);
            $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
            $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
            return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Generates a version 5 UUID based on namespace and name
     * 
     * @param string $namespace Base UUID for namespace
     * @param string $name Name to hash
     * @return string|null Generated UUID v5 or null on failure
     */
    public static function generateUuidV5(
        string $namespace,
        string $name
    ): ?string {
        if (!self::isUuid($namespace)) {
            return null;
        }

        try {
            $nsBytes = self::uuidToBytes($namespace);
            $hash = sha1($nsBytes . $name, true);

            $hash[6] = chr(ord($hash[6]) & 0x0f | 0x50);
            $hash[8] = chr(ord($hash[8]) & 0x3f | 0x80);

            return self::bytesToUuid($hash);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Generates a short UUID (22 characters)
     * 
     * @return string|null Short UUID or null on failure
     */
    public static function generateShortUuid(): ?string
    {
        try {
            $data = random_bytes(16);
            return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Checks if string is a valid UUID
     * 
     * @param string $uuid String to validate
     * @return bool True if valid UUID
     */
    public static function isUuid(string $uuid): bool
    {
        return preg_match(self::UUID_PATTERN, $uuid) === 1;
    }

    /**
     * Checks if string is a valid UUID version 4
     * 
     * @param string $uuid String to validate
     * @return bool True if valid UUID v4
     */
    public static function isUuidV4(string $uuid): bool
    {
        return preg_match(self::UUID_V4_PATTERN, $uuid) === 1;
    }

    /**
     * Normalizes UUID to lowercase and trims spaces
     * 
     * @param string $uuid UUID to normalize
     * @return string Normalized UUID
     */
    public static function normalizeUuid(string $uuid): string
    {
        return strtolower(trim($uuid));
    }

    /**
     * Extracts UUID version
     * 
     * @param string $uuid UUID to analyze
     * @return int|null UUID version or null if invalid
     */
    public static function getUuidVersion(string $uuid): ?int
    {
        if (!self::isUuid($uuid)) {
            return null;
        }

        $parts = explode('-', $uuid);
        $versionHex = $parts[2][0];

        return hexdec($versionHex);
    }

    /**
     * Encrypts data of any type using AES encryption
     * 
     * @param mixed $data Data to encrypt (any type)
     * @param string $key Encryption key
     * @param string $method Encryption method
     * @return string|null Encrypted data
     */
    public static function encrypt(
        $data,
        string $key,
        string $method = 'AES-256-GCM'
    ): ?string {
        // Check if OpenSSL extension is installed
        if (!extension_loaded('openssl')) {
            throw new \RuntimeException('OpenSSL extension is not installed or enabled');
        }

        if (!in_array($method, self::$cipherMethods)) {
            return null;
        }

        // Serialize data to preserve type
        $serializedData = serialize($data);

        $ivLength = openssl_cipher_iv_length($method);
        if ($ivLength === false) {
            return null;
        }

        try {
            $iv = random_bytes($ivLength);
        } catch (\Exception $e) {
            return null;
        }

        $hashedKey = hash('sha256', $key, true);
        if ($hashedKey === false) {
            return null;
        }

        $tag = '';
        $options = OPENSSL_RAW_DATA;
        $encrypted = openssl_encrypt($serializedData, $method, $hashedKey, $options, $iv, $tag);

        if ($encrypted === false) {
            return null;
        }

        // Prepare encrypted string based on method
        if (strpos($method, 'GCM') !== false) {
            $result = base64_encode($iv . $tag . $encrypted);
        } else {
            $result = base64_encode($iv . $encrypted);
        }

        // Make URL-safe (remove problematic characters)
        return rtrim(strtr($result, '+/=', '-_,'), '_,');
    }

    /**
     * Decrypts data encrypted with encrypt() method
     * 
     * @param string $encryptedData Encrypted data (URL-safe base64 encoded)
     * @param string $key Decryption key
     * @param string $method Encryption method used
     * @return mixed|null Original data with preserved type or null on failure
     */
    public static function decrypt(
        string $encryptedData,
        string $key,
        string $method = 'AES-256-GCM'
    ): mixed {
        // Check if OpenSSL extension is installed
        if (!extension_loaded('openssl')) {
            throw new \RuntimeException('OpenSSL extension is not installed or enabled');
        }

        // Convert from URL-safe format
        $data = strtr($encryptedData, '-_,', '+/=');

        // Add padding if needed
        $padding = strlen($data) % 4;
        if ($padding > 0) {
            $data .= str_repeat('=', 4 - $padding);
        }

        $data = base64_decode($data);
        if ($data === false) {
            return null;
        }

        $hashedKey = hash('sha256', $key, true);
        if ($hashedKey === false) {
            return null;
        }

        $ivLength = openssl_cipher_iv_length($method);
        if ($ivLength === false) {
            return null;
        }

        $tagLength = 16;
        $options = OPENSSL_RAW_DATA;

        if (strlen($data) < $ivLength) {
            return null;
        }

        if (strpos($method, 'GCM') !== false) {
            if (strlen($data) < $ivLength + $tagLength) {
                return null;
            }

            $iv = substr($data, 0, $ivLength);
            $tag = substr($data, $ivLength, $tagLength);
            $encrypted = substr($data, $ivLength + $tagLength);

            $decrypted = openssl_decrypt(
                $encrypted,
                $method,
                $hashedKey,
                $options,
                $iv,
                $tag
            );
        } else {
            $iv = substr($data, 0, $ivLength);
            $encrypted = substr($data, $ivLength);

            $decrypted = openssl_decrypt(
                $encrypted,
                $method,
                $hashedKey,
                $options,
                $iv
            );
        }

        if ($decrypted === false) {
            return null;
        }

        return unserialize($decrypted);
    }

    /**
     * Generates cryptographically secure token
     * 
     * @param int $length Token length in bytes
     * @return string|null Generated token or null on failure
     */
    public static function generateToken(int $length = 32): ?string
    {
        try {
            return bin2hex(random_bytes($length));
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Creates HMAC signature for data
     * 
     * @param string $data Data to sign
     * @param string $key Secret key
     * @param string $algo Hashing algorithm
     * @return string|null HMAC signature or null on failure
     */
    public static function createHmac(
        string $data,
        string $key,
        string $algo = 'sha256'
    ): ?string {
        $result = hash_hmac($algo, $data, $key);

        return $result !== false ? $result : null;
    }

    /**
     * Verifies HMAC signature
     * 
     * @param string $data Original data
     * @param string $signature HMAC signature to verify
     * @param string $key Secret key
     * @param string $algo Hashing algorithm
     * @return bool True if signature is valid
     */
    public static function verifyHmac(
        string $data,
        string $signature,
        string $key,
        string $algo = 'sha256'
    ): bool {
        $calculatedSignature = self::createHmac($data, $key, $algo);
        if ($calculatedSignature === null) {
            return false;
        }

        return hash_equals($calculatedSignature, $signature);
    }

    /**
     * Encodes data to URL-safe base64
     * 
     * @param string $data Data to encode
     * @return string|null URL-safe base64 encoded string or null on failure
     */
    public static function base64UrlEncode(string $data): ?string
    {
        $encoded = base64_encode($data);
        if ($encoded === false) {
            return null;
        }

        return rtrim(strtr($encoded, '+/', '-_'), '=');
    }

    /**
     * Decodes URL-safe base64 encoded data
     * 
     * @param string $data URL-safe base64 encoded string
     * @return string|null Decoded data or null on failure
     */
    public static function base64UrlDecode(string $data): ?string
    {
        $padding = strlen($data) % 4;
        if ($padding) {
            $data .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'));

        return $decoded !== false ? $decoded : null;
    }

    /**
     * Generates cryptographic key
     * 
     * @param int $length Key length in bytes
     * @return string|null Generated key or null on failure
     */
    public static function generateKey(int $length = 32): ?string
    {
        try {
            return random_bytes($length);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Converts UUID string to binary format
     * 
     * @param string $uuid UUID string
     * @return string|null Binary representation or null on failure
     */
    private static function uuidToBytes(string $uuid): ?string
    {
        $uuid = str_replace('-', '', $uuid);
        $binary = hex2bin($uuid);

        return $binary !== false ? $binary : null;
    }

    /**
     * Converts binary data to UUID string
     * 
     * @param string $bytes Binary data
     * @return string UUID string
     */
    private static function bytesToUuid(string $bytes): string
    {
        $hex = bin2hex($bytes);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split($hex, 4));
    }
}
