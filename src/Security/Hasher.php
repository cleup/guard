<?php

namespace Cleup\Guard\Security;

/**
 * Advanced hashing class for password hashing and verification
 * Provides secure password handling and hash utilities
 */
class Hasher
{
    private const DEFAULT_ALGORITHM = PASSWORD_BCRYPT;
    private const DEFAULT_OPTIONS = [
        'cost' => 12
    ];

    /**
     * Hashes a password using secure algorithm
     * 
     * @param string $password Password to hash
     * @param array $options Hashing options
     * @return string|null Hashed password or null on failure
     */
    public static function hashPassword(string $password, array $options = []): ?string
    {
        $options = array_merge(self::DEFAULT_OPTIONS, $options);

        $hashed = password_hash($password, self::DEFAULT_ALGORITHM, $options);
        return $hashed !== false ? $hashed : null;
    }

    /**
     * Verifies password against a hash
     * 
     * @param string $password Plain text password
     * @param string $hash Hashed password
     * @return bool True if password matches
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Checks if password needs rehashing
     * 
     * @param string $hash Hashed password
     * @param array $options New options to check against
     * @return bool|null True if password needs rehashing, null on failure
     */
    public static function needsRehash(string $hash, array $options = []): ?bool
    {
        $options = array_merge(self::DEFAULT_OPTIONS, $options);

        $result = password_needs_rehash($hash, self::DEFAULT_ALGORITHM, $options);
        return $result !== null ? $result : null;
    }

    /**
     * Generates cryptographically secure password
     * 
     * @param int $length Password length
     * @param bool $useUpper Include uppercase letters
     * @param bool $useLower Include lowercase letters
     * @param bool $useNumbers Include numbers
     * @param bool $useSpecial Include special characters
     * @return string|null Generated password or null on failure
     */
    public static function generatePassword(
        int $length = 16,
        bool $useUpper = true,
        bool $useLower = true,
        bool $useNumbers = true,
        bool $useSpecial = true
    ): ?string {
        $chars = '';
        $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $lower = 'abcdefghjkmnpqrstuvwxyz';
        $numbers = '23456789';
        $special = '!@#$%^&*()-_=+[]{}|;:,.<>?';

        if ($useUpper) $chars .= $upper;
        if ($useLower) $chars .= $lower;
        if ($useNumbers) $chars .= $numbers;
        if ($useSpecial) $chars .= $special;

        if (empty($chars)) {
            return null;
        }

        try {
            $password = '';
            $charsLength = strlen($chars);

            // Ensure at least one character from each selected set
            if ($useUpper) $password .= $upper[random_int(0, strlen($upper) - 1)];
            if ($useLower) $password .= $lower[random_int(0, strlen($lower) - 1)];
            if ($useNumbers) $password .= $numbers[random_int(0, strlen($numbers) - 1)];
            if ($useSpecial) $password .= $special[random_int(0, strlen($special) - 1)];

            // Fill remaining length
            for ($i = strlen($password); $i < $length; $i++) {
                $password .= $chars[random_int(0, $charsLength - 1)];
            }

            return str_shuffle($password);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Creates a hash of data using specified algorithm
     * 
     * @param string $data Data to hash
     * @param string $algo Hashing algorithm
     * @param bool $binary Output in binary format
     * @return string|null Hash value or null on failure
     */
    public static function hash(string $data, string $algo = 'sha256', bool $binary = false): ?string
    {
        $result = hash($algo, $data, $binary);
        return $result !== false ? $result : null;
    }

    /**
     * Creates HMAC hash of data
     * 
     * @param string $data Data to hash
     * @param string $key Secret key
     * @param string $algo Hashing algorithm
     * @param bool $binary Output in binary format
     * @return string|null HMAC hash or null on failure
     */
    public static function hmac(string $data, string $key, string $algo = 'sha256', bool $binary = false): ?string
    {
        $result = hash_hmac($algo, $data, $key, $binary);
        return $result !== false ? $result : null;
    }

    /**
     * Verifies HMAC hash
     * 
     * @param string $data Original data
     * @param string $hash HMAC hash to verify
     * @param string $key Secret key
     * @param string $algo Hashing algorithm
     * @return bool True if hash is valid
     */
    public static function verifyHmac(string $data, string $hash, string $key, string $algo = 'sha256'): bool
    {
        $calculatedHash = self::hmac($data, $key, $algo);
        if ($calculatedHash === null) {
            return false;
        }

        return hash_equals($calculatedHash, $hash);
    }

    /**
     * Gets information about a password hash
     * 
     * @param string $hash Password hash
     * @return array|null Hash information or null on failure
     */
    public static function getHashInfo(string $hash): ?array
    {
        $info = password_get_info($hash);
        return $info !== false ? $info : null;
    }

    /**
     * Creates a timing attack safe string comparison
     * 
     * @param string $knownString Known string
     * @param string $userString User provided string
     * @return bool True if strings are equal
     */
    public static function timingSafeCompare(string $knownString, string $userString): bool
    {
        return hash_equals($knownString, $userString);
    }

    /**
     * Generates a random string with specified characters
     * 
     * @param int $length String length
     * @param string $characters Character set to use
     * @return string|null Random string or null on failure
     */
    public static function randomString(
        int $length,
        string $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ): ?string {
        try {
            $result = '';
            $max = strlen($characters) - 1;

            for ($i = 0; $i < $length; $i++) {
                $result .= $characters[random_int(0, $max)];
            }

            return $result;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Creates a hash for file verification
     * 
     * @param string $filePath Path to file
     * @param string $algo Hashing algorithm
     * @return string|null File hash or null on failure
     */
    public static function hashFile(string $filePath, string $algo = 'sha256'): ?string
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            return null;
        }

        $hash = hash_file($algo, $filePath);
        return $hash !== false ? $hash : null;
    }

    /**
     * Verifies file against a hash
     * 
     * @param string $filePath Path to file
     * @param string $expectedHash Expected hash value
     * @param string $algo Hashing algorithm
     * @return bool True if file hash matches expected hash
     */
    public static function verifyFile(string $filePath, string $expectedHash, string $algo = 'sha256'): bool
    {
        $actualHash = self::hashFile($filePath, $algo);
        if ($actualHash === null) {
            return false;
        }

        return hash_equals($expectedHash, $actualHash);
    }

    /**
     * Creates a password hash using Argon2 algorithm
     * 
     * @param string $password Password to hash
     * @param array $options Hashing options
     * @return string|null Hashed password or null on failure
     */
    public static function hashArgon2(string $password, array $options = []): ?string
    {
        $defaultOptions = [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 1
        ];

        $options = array_merge($defaultOptions, $options);

        $hashed = password_hash($password, PASSWORD_ARGON2I, $options);
        return $hashed !== false ? $hashed : null;
    }

    /**
     * Creates a password hash using Argon2id algorithm
     * 
     * @param string $password Password to hash
     * @param array $options Hashing options
     * @return string|null Hashed password or null on failure
     */
    public static function hashArgon2id(string $password, array $options = []): ?string
    {
        $defaultOptions = [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 1
        ];

        $options = array_merge($defaultOptions, $options);

        $hashed = password_hash($password, PASSWORD_ARGON2ID, $options);
        return $hashed !== false ? $hashed : null;
    }

    /**
     * Checks if hash uses weak algorithm
     * 
     * @param string $hash Hash to check
     * @return bool True if hash uses weak algorithm
     */
    public static function isWeakHash(string $hash): bool
    {
        $info = self::getHashInfo($hash);
        if ($info === null) {
            return true;
        }

        // Check for weak algorithms
        $weakAlgorithms = [PASSWORD_DEFAULT, PASSWORD_BCRYPT];
        if (isset($info['algo']) && !in_array($info['algo'], $weakAlgorithms, true)) {
            return true;
        }

        // Check for weak options
        if (isset($info['options']['cost']) && $info['options']['cost'] < 10) {
            return true;
        }

        return false;
    }
}
