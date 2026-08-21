# Valid
A robust validation class that provides comprehensive methods for verifying various data formats including emails, URLs, dates, colors, passwords, and network addresses.

## Features

- Email, URL, domain, and host validation
- Phone number and IP address verification
- Date and time validation utilities
- Comprehensive color format validation (HEX, RGB, RGBA, HSL, HSLA)
- Password strength checking
- JSON and special format validation
- Length and complexity checks
- Security checks (null bytes, dangerous protocols, Unicode bombs, long lines)

## Basic Usage

```php
use Cleup\Guard\Purifier\Utils\Valid;

// --- Network Validation ---
// Email validation
$isEmail = Valid::email('user@example.com');
// Returns: true

// URL validation
$isUrl = Valid::url('https://example.com');
// Returns: true
$isUrlWithScheme = Valid::url('example.com', true);
// Returns: false (requires http:// or https://)

// URL protocol validation
$validProtocol = Valid::allowedProtocol('https://site.com', ['https', 'ftp']);
// Returns: true

// URL host validation
$validHost = Valid::allowedHost('https://sub.example.com', 'example.com');
// Returns: true (supports subdomains)
$validHostArray = Valid::allowedHost('https://example.com', ['example.com', 'another.com']);
// Returns: true (supports array of allowed hosts)

// Domain validation
$isDomain = Valid::domain('example.com');
// Returns: true
$isIdnDomain = Valid::domain('пример.рф');
// Returns: true (supports IDN)
$isLongDomain = Valid::domain(str_repeat('a', 254) . '.com');
// Returns: false (max length: 253)

// IP address validation
$isIp = Valid::ip('192.168.1.1');
// Returns: true
$isIpv4 = Valid::ipv4('192.168.1.1');
// Returns: true
$isIpv6 = Valid::ipv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334');
// Returns: true

// Phone number validation
$isPhone = Valid::phone('+1-234-567-8900');
// Returns: true
$isRussianPhone = Valid::phone('+7 (999) 123-45-67');
// Returns: true (supports Russian numbers)
$isShortPhone = Valid::phone('1234567');
// Returns: false (too short)
$isInvalidPhone = Valid::phone('0000000');
// Returns: false (only 0s)

// --- Date and Time Validation ---
// Date format validation
$isValidDate = Valid::dateFormat('2024-01-15');
// Returns: true
$isValidCustomDate = Valid::dateFormat('15/01/2024', 'd/m/Y');
// Returns: true
$isInvalidDate = Valid::dateFormat('2024-02-30');
// Returns: false (invalid date)

// Date comparison
$isFuture = Valid::futureDate('2024-12-31');
// Returns: true
$isPast = Valid::pastDate('2020-01-01');
// Returns: true
$isToday = Valid::today(date('Y-m-d'));
// Returns: true

// --- Color Validation ---
// HEX color validation
$isHexColor = Valid::hexColor('#ff0000');
// Returns: true
$isHexColorShort = Valid::hexColor('#f00');
// Returns: true
$isHexColorAlpha = Valid::hexColor('#ff000080');
// Returns: true

// RGB color validation
$isRgb = Valid::rgbColor('rgb(255, 100, 50)');
// Returns: true
$isRgbPercent = Valid::rgbColor('rgb(100%, 50%, 0%)');
// Returns: true
$isRgbCss4 = Valid::rgbColor('rgb(255 100 50)');
// Returns: true (CSS Color Level 4 syntax)

// RGBA color validation
$isRgba = Valid::rgbaColor('rgba(255, 100, 50, 0.5)');
// Returns: true
$isRgbaCss4 = Valid::rgbaColor('rgba(255 100 50 / 0.5)');
// Returns: true (CSS Color Level 4 syntax)

// HSL color validation
$isHsl = Valid::hslColor('hsl(360, 100%, 50%)');
// Returns: true
$isHslCss4 = Valid::hslColor('hsl(360 100% 50%)');
// Returns: true (CSS Color Level 4 syntax)

// HSLA color validation
$isHsla = Valid::hslaColor('hsla(360, 100%, 50%, 0.5)');
 // Returns: true
$isHslaCss4 = Valid::hslaColor('hsla(360 100% 50% / 0.5)');
// Returns: true (CSS Color Level 4 syntax)

// CSS color validation (HEX, RGB, RGBA, HSL, HSLA)
$isCssColor = Valid::cssColor('#fff');
// Returns: true

// --- String Validation ---
// Latin characters only
$isLatin = Valid::latin('Hello');
// Returns: true
$isLatinWithSpaces = Valid::latin('Hello World', true);
// Returns: true (allows spaces)
$isLatinWithNumbers = Valid::latin('Hello123', false, true);
// Returns: true (allows numbers)

// Number validation
$isPositive = Valid::positiveNumber(5);
// Returns: true
$isNegative = Valid::negativeNumber(-5);
// Returns: true
$isEven = Valid::even(4);
// Returns: true
$isOdd = Valid::odd(3);
// Returns: true
$isLeapYear = Valid::leapYear(2024);
// Returns: true

// Password strength
$isStrong = Valid::strongPassword('MyPass123!');
// Returns: true (min 8 chars, uppercase, lowercase, digit, special char)
$isStrongNoCyrillic = Valid::strongPassword('MyPass123!', false);
// Returns: true (disallows Cyrillic)
$isWeak = Valid::strongPassword('123');
// Returns: false (too short)

// Palindrome check
$isPalindrome = Valid::palindrome('racecar');
// Returns: true
$isPalindromeWithSpaces = Valid::palindrome('A man a plan a canal Panama');
// Returns: true

// Roman numeral validation
$isRoman = Valid::romanNumeral('XIV');
// Returns: true
$isRomanLowercase = Valid::romanNumeral('xiv', true);
// Returns: true (allows lowercase)

// MAC address validation
$isMac = Valid::macAddress('00:1B:44:11:3A\:B7');
// Returns: true
$isMacHyphen = Valid::macAddress('00-1B-44-11-3A-B7');
// Returns: true
$isMacDotted = Valid::macAddress('001B.4411.3AB7');
// Returns: true

// --- Data Format Validation ---
// JSON validation
$isJson = Valid::json('{"key": "value"}');
// Returns: true
$isJsonScalar = Valid::json('"hello"', true);
// Returns: true (allows scalar values)
$isInvalidJson = Valid::json('{key: "value"}');
// Returns: false (invalid JSON)

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
// Returns: true (default separators: '-', '_')
$isValidCustomSlug = Valid::slug('my_valid_slug', '_', 100);
// Returns: true (custom separator: '_')
$isInvalidSlug = Valid::slug('my--slug');
// Returns: false (duplicate separator)

// Non-empty check
$notEmpty = Valid::notEmpty(' text ');
// Returns: true

// --- Security Validation ---
// Null bytes check
$hasNullBytes = Valid::nullBytes("Hello\x00World");
// Returns: true
$noNullBytes = Valid::noNullBytes("Hello World");
// Returns: true

// Dangerous protocols check
$hasDangerousProtocol = Valid::dangerousProtocols('<script src="javascript\:alert(1)">');
// Returns: true
$safeProtocols = Valid::safeProtocols('<a href="https://example.com">Link</a>');
// Returns: true

// Unicode BOM check
$hasUnicodeBomb = Valid::unicodeBomb("\xEF\xBB\xBFHello");
// Returns: true
$noUnicodeBomb = Valid::noUnicodeBomb("Hello");
// Returns: true

// Long lines check
$hasLongLines = Valid::longLines(str_repeat('a', 10001));
// Returns: true
$reasonableLines = Valid::reasonableLineLength(str_repeat('a', 10000));
// Returns: true

// Overall danger check
$isDangerous = Valid::dangerous("Hello\x00World");
// Returns: true
$isSafe = Valid::safeChars("Hello World");
// Returns: true