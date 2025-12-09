# JWT Handler

A simple but powerful PHP class for working with JSON web tokens (JWT).

### Features
- Support for all major algorithms (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, EdDSA)
- Automatic token expiration management
- Secure signature verification with constant-time comparison
- Detailed error messages

### Quick Start

```php
use Cleup\Guard\Security\JWT;

// Create token
$jwt = new JWT('your-secret-key');
$token = $jwt->encode([
    'user_id' => 123,
    'username' => 'john_doe'
]);

// Decode token
$payload = $jwt->decode($token);
echo $payload['user_id']; // 123
```

### Fluent Interface Examples
```php
// Full configuration
$token = $jwt
    ->algorithm('HS512')     // Use HS512 algorithm
    ->expiresIn(7200)         // Valid for 2 hours
    ->leeway(60)              // 60-second time leeway
    ->encode([
        'user_id' => 123,
        'role' => 'admin'
    ]);

// Set exact expiration time
$token = $jwt
    ->expiresAt(time() + 3600)
    ->encode(['data' => 'test']);

```

### Supported Algorithms
- HMAC: HS256, HS384, HS512
- RSA: RS256, RS384, RS512
- ECDSA: ES256, ES384, ES256K
- Edwards-curve: EdDSA

### Security Notes
- Use strong secret keys (min 32 chars for HS256)
- Store keys securely (environment variables, vaults)
- Set reasonable token expiration times
- Use HTTPS for token transmission
- Regularly rotate keys in production
