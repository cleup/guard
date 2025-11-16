# Valid
A robust validation class that provides comprehensive methods for verifying various data formats including emails, URLs, dates, colors, passwords, and network addresses.

## Features
- Email, URL, and domain validation
- Phone number and IP address verification
- Date and time validation utilities
- Comprehensive color format validation (HEX, RGB, RGBA, HSL, HSLA)
- Password strength checking
- JSON and special format validation
- Length and complexity checks

## Basic Usage
```php
use Cleup\Guard\Purifier\Utils\Valid;

// Email validation
$isEmail = Valid::email('user@example.com');
// Returns: true

// URL validation
$isUrl = Valid::url('https://example.com');
// Returns: true

// URL protocol validation
$validProtocol = Valid::allowedProtocol('https://site.com', ['https', 'ftp']);
// Returns: true

// URL host validation
$validHost = Valid::allowedHost('https://sub.example.com', 'example.com');
// Returns: true

// Domain validation
$isDomain = Valid::domain('example.com');
// Returns: true

// IP address validation
$isIp = Valid::ip('192.168.1.1');
// Returns: true

// Phone number validation
$isPhone = Valid::phone('+1-234-567-8900');
// Returns: true

// Date format validation
$isValidDate = Valid::dateFormat('2024-01-15');
// Returns: true

// HEX color validation
$isHexColor = Valid::hexColor('#ff0000');
// Returns: true

// RGB color validation
$isRgb = Valid::rgbColor('rgb(255, 100, 50)');
// Returns: true

// RGBA color validation
$isRgba = Valid::rgbaColor('rgba(255, 100, 50, 0.5)');
// Returns: true

// HSL color validation
$isHsl = Valid::hslColor('hsl(360, 100%, 50%)');
// Returns: true

// HSLA color validation
$isHsla = Valid::hslaColor('hsla(360, 100%, 50%, 0.5)');
// Returns: true

// CSS color validation
$isCssColor = Valid::cssColor('#fff');
// Returns: true

// Latin characters only
$isLatin = Valid::latin('Hello');
// Returns: true

// Number validation
$isPositive = Valid::positiveNumber(5);
// Returns: true
$isNegative = Valid::negativeNumber(-5);
// Returns: true
$isEven = Valid::even(4);
// Returns: true
$isOdd = Valid::odd(3);
// Returns: true

// Leap year validation
$isLeapYear = Valid::leapYear(2024);
// Returns: true

// Date comparison
$isFuture = Valid::futureDate('2024-12-31');
// Returns: true
$isPast = Valid::pastDate('2020-01-01');
// Returns: true
$isToday = Valid::today(date('Y-m-d'));
// Returns: true

// Password strength
$isStrong = Valid::strongPassword('MyPass123!');
// Returns: true

// Palindrome check
$isPalindrome = Valid::palindrome('racecar');
// Returns: true

// Roman numeral validation
$isRoman = Valid::romanNumeral('XIV');
// Returns: true

// MAC address validation
$isMac = Valid::macAddress('00:1B:44:11:3A:B7');
// Returns: true

// JSON validation
$isJson = Valid::json('{"key": "value"}');
// Returns: true

// Emoji detection
$hasEmoji = Valid::containsEmoji('Hello 😊');
// Returns: true

// Bitcoin address validation
$isBitcoin = Valid::bitcoinAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
// Returns: true

// Length validation
$withinMax = Valid::maxLength('text', 10);
// Returns: true
$meetsMin = Valid::minLength('text', 3);
// Returns: true

// Slug validation
$isValidSlug = Valid::slug('my-valid-slug');
// Returns: true

// Non-empty check
$notEmpty = Valid::notEmpty(' text ');
// Returns: true
```