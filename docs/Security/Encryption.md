# Encryption
A utility class for cryptographic operations, including UUID generation, data encryption/decryption, and security utilities.

## Features:
- UUID v4 and v5 generation, including short UUIDs
- AES encryption/decryption (AES-256-GCM, AES-256-CBC, AES-128-GCM, AES-128-CBC)
- HMAC signature creation and verification with constant-time comparison
- Cryptographic token and key generation
- String encoding/decoding utilities

## Supported Cipher Methods:
- `AES-256-GCM` (recommended)
- `AES-256-CBC`
- `AES-128-GCM`
- `AES-128-CBC`

## Usage Examples

```php
use Cleup\Guard\Security\Encryption;

// --- UUID Generation ---
// Generate a version 4 (random) UUID
$uuid = Encryption::generateUuid(); // e.g., "550e8400-e29b-41d4-a716-446655440000" or null on failure

// Generate a version 5 UUID (namespace-based)
$namespace = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'; // Example namespace (DNS)
$uuid5 = Encryption::generateUuidV5($namespace, 'example.com'); // UUID v5 or null if namespace is invalid

// Generate a short UUID (22 characters)
$shortUuid = Encryption::generateShortUuid(); // e.g., "dQw4w9WgXcQ" or null on failure

// --- UUID Validation ---
// Check if a string is a valid UUID
$isValidUuid = Encryption::isUuid('550e8400-e29b-41d4-a716-446655440000'); // true
$isValidUuid = Encryption::isUuid('invalid-uuid'); // false

// Check if a UUID is version 4
$isV4 = Encryption::isUuidV4('550e8400-e29b-41d4-a716-446655440000'); // true

// Get UUID version (1-5)
$version = Encryption::getUuidVersion('550e8400-e29b-41d4-a716-446655440000'); // 4
$version = Encryption::getUuidVersion('invalid-uuid'); // null

// Normalize UUID (convert to lowercase and trim spaces)
$normalized = Encryption::normalizeUuid('  550E8400-E29B-41D4-A716-446655440000  '); // "550e8400-e29b-41d4-a716-446655440000"

// --- Encryption/Decryption ---
// Encrypt data (supports any type: string, array, object, etc.)
// The key is automatically hashed using SHA-256
$encrypted = Encryption::encrypt('secret data', 'my-secret-key', 'AES-256-GCM'); // String or null on failure
$encryptedArray = Encryption::encrypt(['key' => 'value'], 'my-secret-key'); // Works with arrays

// Decrypt data (restores original type)
$decrypted = Encryption::decrypt($encrypted, 'my-secret-key', 'AES-256-GCM'); // 'secret data'
$decryptedArray = Encryption::decrypt($encryptedArray, 'my-secret-key'); // ['key' => 'value']

// Encryption/decryption errors
$invalidMethod = Encryption::encrypt('data', 'key', 'AES-128-ECB'); // null (unsupported method)
$invalidDecrypt = Encryption::decrypt('invalid-data', 'key'); // null (corrupted data)

// --- Security Utilities ---
// Generate a cryptographic token
$token = Encryption::generateToken(32); // String or null on failure

// Generate a cryptographic key
$key = Encryption::generateKey(32); // String or null on failure

// Create an HMAC signature
$signature = Encryption::createHmac('data', 'secret-key'); // String or null on failure
$signatureMd5 = Encryption::createHmac('data', 'secret-key', 'md5'); // String

// Verify an HMAC signature (uses constant-time comparison for security)
$isValid = Encryption::verifyHmac('data', $signature, 'secret-key'); // true or false
$isValid = Encryption::verifyHmac('data', 'invalid-signature', 'secret-key'); // false

// --- String Encoding ---
// Encode a string
$encoded = Encryption::base64UrlEncode('data to encode'); // String or null on failure

// Decode a string
$decoded = Encryption::base64UrlDecode($encoded); // String or null on failure