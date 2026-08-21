# Scrub

A comprehensive sanitization utility class that provides methods for cleaning, filtering, and normalizing various types of input data including strings, emails, URLs, and special characters.

## Features

- HTML escaping and entity encoding
- Email and URL sanitization
- String normalization and whitespace handling
- Slug generation and Cyrillic transliteration
- Text cleaning with emoji removal
- Numeric and string conversion utilities
- Safe truncation with prefix/suffix support
- Content neutralization (removing null bytes, disabling dangerous protocols, defusing Unicode bombs, breaking long lines)

## Basic Usage

```php
use Cleup\Guard\Purifier\Utils\Scrub;

// HTML escaping
$safeOutput = Scrub::escape('<script>alert("xss")</script>');
// Returns: &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;

// Email sanitization
$cleanEmail = Scrub::email('  user@example.com  ');
// Returns: 'user@example.com'
$invalidEmail = Scrub::email('invalid-email');
// Returns: null

// HTML entity encoding
$encoded = Scrub::encode('Copyright © 2024');
// Returns: 'Copyright &copy; 2024'

// URL validation
$validUrl = Scrub::url('https://example.com/path');
// Returns: 'https://example.com/path'
$invalidUrl = Scrub::url('not-a-url');
// Returns: null

// Extract digits only
$digits = Scrub::digits('+1 (234) 567-89-00');
// Returns: '12345678900'

// Remove whitespace
$noSpaces = Scrub::stripWhitespace('Hello World 123');
// Returns: 'HelloWorld123'

// String normalization
$normalized = Scrub::normalizeString("Hello    World\n\nTest");
// Returns: 'Hello World\nTest'

// Slug generation
$slug = Scrub::slug('My Clean URL Title!');
// Returns: 'my-clean-url-title' (default separators: '-', '_')
$customSlug = Scrub::slug('My Slug', '_', 10);
// Returns: 'my_slug' (only '_' separator)

// Cyrillic transliteration
$translit = Scrub::translitCyrillic('Привет Мир');
// Returns: 'privet-mir' (default separator: 'both', i.e., '-' and '_')
$upperTranslit = Scrub::translitCyrillic('Привет', '-', true);
// Returns: 'PRIVET'

// Numeric conversion
$number = Scrub::toNumeric('123.45');
$number = Scrub::toNumeric('123,45');
// Returns: 123.45 (float)
$intNumber = Scrub::toNumeric('123');
// Returns: 123 (int)
$zero = Scrub::toNumeric('abc');
// Returns: 0 (int)
// Note: Commas (',') are automatically replaced with dots ('.')

// String conversion
$stringFromArray = Scrub::toString(['key' => 'value']);
// Returns: '{"key":"value"}'
$stringFromBool = Scrub::toString(true);
// Returns: 'true'

// Text cleaning
$cleanText = Scrub::text('Hello 😊 <b>World</b>!');
// Returns: 'Hello World!'
// Removes HTML tags, emojis, and special characters, keeping only letters, numbers, spaces, and basic punctuation.

// String truncation
$shortText = Scrub::truncate('Long text here', 8, '...');
// Returns: 'Long tex...'
$reverseTruncate = Scrub::truncate('Long text here', 8, '...', '', true);
// Returns: 'xt here...'
$arrayTruncate = Scrub::truncate('Long text here', [2, 6], '...');
// Returns: 'ng tex...'

// Content neutralization
$neutralized = Scrub::neutralize($content);
// Removes null bytes, defuses Unicode bombs, and breaks long lines

// Deprecated methods (for backward compatibility)
$oldUrl = Scrub::filterUrl('https://example.com');
$oldText = Scrub::filterText('Some text');
