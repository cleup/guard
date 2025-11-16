# Hasher
Secure password hashing, verification, and cryptographic utilities

## Features:
- Bcrypt, Argon2, and Argon2id password hashing
- Secure password generation with customizable character sets
- File integrity verification with hash checking
- HMAC signatures and verification
- Timing-attack safe string comparison
- Weak hash detection and rehashing support

## Basic Usage
```php
use Cleup\Guard\Security\Hasher;

// Password Hashing & Verification
$hash = Hasher::hashPassword('password');              // bcrypt hash
$valid = Hasher::verifyPassword('password', $hash);    // true/false
$rehash = Hasher::needsRehash($hash, ['cost' => 12]);  // check if outdated

// Modern Algorithms
$argon2 = Hasher::hashArgon2('password');              // Argon2 hash
$argon2id = Hasher::hashArgon2id('password');          // Argon2id hash

// Password Generation
$password = Hasher::generatePassword(16, true, true, true, true); // "A1b!cD2@eF3#gH4$"

// Hashing Functions
$hash = Hasher::hash('data', 'sha256');                // SHA-256 hash
$hmac = Hasher::hmac('data', 'key', 'sha256');         // HMAC hash
$valid = Hasher::verifyHmac('data', $hmac, 'key');     // verify HMAC

// File Operations
$fileHash = Hasher::hashFile('/path/file.txt');        // file checksum
$valid = Hasher::verifyFile('/path/file.txt', $hash);  // verify integrity

// Utilities
$random = Hasher::randomString(32);                    // secure random string
$safe = Hasher::timingSafeCompare($str1, $str2);       // constant-time compare
$info = Hasher::getHashInfo($hash);                    // hash algorithm info
$weak = Hasher::isWeakHash($hash);                     // check weak algorithms
```