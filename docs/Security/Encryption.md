# Encryption 
Advanced encryption utility for UUID generation, data encryption/decryption, and security operations

## Features:
- UUID v4/v5 generation and validation
- AES-256-GCM/CBC encryption with automatic IV generation
- HMAC signatures with constant-time verification
- Cryptographic key and token generation
- URL-safe base64 encoding

## Basic Usage
```php
use Cleup\Guard\Security\Encryption;

// UUID Generation
$uuid = Encryption::generateUuid();                    // "550e8400-e29b-41d4-a716-446655440000"
$uuid5 = Encryption::generateUuidV5($namespace, 'name'); // Version 5 UUID
$short = Encryption::generateShortUuid();              // "dQw4w9WgXcQ" (22 chars)

// UUID Validation
$valid = Encryption::isUuid('550e8400-e29b-41d4-a716-446655440000'); // true
$isV4 = Encryption::isUuidV4($uuid);                   // true
$version = Encryption::getUuidVersion($uuid);          // 4
$normalized = Encryption::normalizeUuid($uuid);        // lowercase trimmed

// Encryption/Decryption
$encrypted = Encryption::encrypt('secret', 'key', 'AES-256-GCM'); // base64
$decrypted = Encryption::decrypt($encrypted, 'key', 'AES-256-GCM'); // 'secret'

// Security Utilities
$token = Encryption::generateToken(32);                // 64-char hex token
$key = Encryption::generateKey(32);                    // 32-byte random key
$signature = Encryption::createHmac('data', 'key');    // HMAC signature
$valid = Encryption::verifyHmac('data', $sig, 'key');  // verify HMAC

// Base64 URL
$encoded = Encryption::base64UrlEncode('data');        // URL-safe base64
$decoded = Encryption::base64UrlDecode($encoded);      // original data
```