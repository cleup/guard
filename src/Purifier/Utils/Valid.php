<?php

namespace Cleup\Guard\Purifier\Utils;

use DateTime;

class Valid
{
    /**
     * Checks if a string is a valid email address.
     *
     * @param string $email The email to validate.
     * @return bool
     */
    public static function email(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Validates if a string is a properly formatted URL.
     *
     * @param string $url The URL string to validate
     * @param bool $requireScheme Whether to require a scheme (http/https) in the URL
     * @return bool
     */
    public static function url(string $url, bool $requireScheme = true): bool
    {
        if ($requireScheme && !preg_match('~^https?://~i', $url)) {
            return false;
        }

        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    /**
     * Validates that a URL string uses one of the allowed protocols
     * 
     * @param string $url - The URL to validate
     * @param array|string $allowedProtocols - A string or array of allowed protocols
     * @return bool
     */
    public static function allowedProtocol(
        string $url,
        array|string $allowedProtocols = ['http', 'https', 'ftp']
    ): bool {
        if (is_string($allowedProtocols))
            $allowedProtocols = [$allowedProtocols];

        $parsed = parse_url($url);

        if (!isset($parsed['scheme'])) {
            return false;
        }

        return in_array(
            strtolower($parsed['scheme']),
            array_map('strtolower', $allowedProtocols)
        );
    }

    /**
     * Validates that a URL's host is in the list of allowed hosts
     * 
     * @param string $url - The URL to validate
     * @param array|string $allowedHosts - A string or array of allowed hosts
     * @return bool
     */
    public static function allowedHost(string $url, array|string $allowedHosts): bool
    {
        if (is_string($allowedHosts)) {
            $allowedHosts = [$allowedHosts];
        }

        $parsed = parse_url($url);

        if (!isset($parsed['host'])) {
            return false;
        }

        $host = strtolower($parsed['host']);
        $allowedHosts = array_map('strtolower', $allowedHosts);

        foreach ($allowedHosts as $allowedHost) {
            if ($host === $allowedHost) {
                return true;
            }

            if (str_ends_with($host, '.' . $allowedHost) && $host !== $allowedHost) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if a string is a valid domain name (without protocol).
     *
     * @param string $domain The domain to validate.
     * @return bool
     */
    public static function domain(string $domain): bool
    {
        if (strlen($domain) > 253) {
            return false;
        }

        // Конвертируем IDN только если есть не-ASCII символы
        if (preg_match('/[^\x00-\x7F]/', $domain)) {
            $converted = idn_to_ascii(
                $domain,
                IDNA_NONTRANSITIONAL_TO_ASCII,
                INTL_IDNA_VARIANT_UTS46
            );

            if ($converted === false) {
                return false;
            }

            $domain = $converted;
        }

        return preg_match(
            '/^(?!-)([a-z0-9-]{1,63})(\.[a-z0-9-]{1,63})*(?<!-)\.([a-z]{2,}|xn--[a-z0-9-]+)$/ix',
            $domain
        ) === 1;
    }

    /**
     * Validates if string is a properly formatted IP address (IPv4 or IPv6).
     *
     * @param string $ip The IP address string to validate
     * @return bool
     */
    public static function ip(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Validates if string is a properly formatted IPv4 address.
     *
     * @param string $ip The IPv4 address string to validate
     * @return bool
     */
    public static function ipv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /**
     * Validates if string is a properly formatted IPv6 address.
     *
     * @param string $ip The IPv6 address string to validate
     * @return bool
     */
    public static function ipv6(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Validates if a string is a properly formatted international phone number.
     * Supports optional '+' prefix and various separators (spaces, hyphens, parentheses).
     *
     * @param string $phone The phone number to validate
     * @return bool
     */
    public static function phone(string $phone): bool
    {
        // Убираем все нецифровые символы для анализа
        $digitsOnly = preg_replace('/[^0-9]/', '', $phone);
        $digitLength = strlen($digitsOnly);
        $hasPlus = str_starts_with($phone, '+');

        if ($digitLength < 7 || $digitLength > 15) {
            return false;
        }

        if ($hasPlus && $digitLength > 15) {
            return false;
        }

        if (!$hasPlus && $digitLength > 11) {
            return false;
        }

        if (preg_match('/^[01]+$/', $digitsOnly)) {
            return false;
        }

        if (preg_match('/(\d)\1{6,}/', $digitsOnly)) {
            return false;
        }

        $patterns = [
            '/^\+\d{1,3}(?:[\s\-]?\d{2,5}){2,4}$/',
            '/^\+7[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}$/',
            '/^8[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}$/',
            '/^7\d{10}$/',
            '/^\d{3}[\s\-]?\d{2}[\s\-]?\d{2}$/',
            '/^\(?\d{3,5}\)?[\s\-]?\d{2,4}[\s\-]?\d{2,4}$/',
            '/^\d{7,11}$/'
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $phone)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validates if a string matches specified date format.
     *
     * @param string $date The date string to validate
     * @param string $format The expected date format (default: 'Y-m-d')
     * @return bool
     */
    public static function dateFormat(string $date, string $format = 'Y-m-d'): bool
    {
        $d = DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) === $date;
    }

    /**
     * Checks if value is not empty (after trimming whitespace).
     *
     * @param mixed $value The value to check
     * @return bool
     */
    public static function notEmpty(mixed $value): bool
    {
        if ($value === null) {
            return false;
        }

        if (is_string($value)) {
            return trim($value) !== '';
        }

        if (is_array($value)) {
            return !empty($value);
        }

        return $value !== '';
    }

    /**
     * Validates if string is a properly formatted HEX color code.
     * 
     * Supports following formats:
     * - #RGB       (3-digit)
     * - #RRGGBB    (6-digit)
     * - #RRGGBBAA  (8-digit with alpha)
     *
     * @param string $value The color string to validate
     * @return bool
     */
    public static function hexColor(string $value): bool
    {
        return preg_match('/^#([a-f0-9]{3,4}|[a-f0-9]{6}|[a-f0-9]{8})$/i', $value) === 1;
    }

    /**
     * Validates RGB color format.
     * 
     * Supports following formats:
     * - rgb(255, 255, 255)
     * - rgb(100%, 100%, 100%)
     * - rgb(255 255 255) - CSS Color Level 4 syntax
     * - With optional spaces after commas
     *
     * @param string $value The RGB color string to validate
     * @return bool
     */
    public static function rgbColor(string $value): bool
    {
        $classicPattern = '/^rgb\(\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . ',\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . ',\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*\)$/i';

        $css4Pattern = '/^rgb\(\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s+'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s+'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*\)$/i';

        return preg_match($classicPattern, $value) === 1 || preg_match($css4Pattern, $value) === 1;
    }

    /**
     * Validates RGBA color format with transparency.
     * 
     * Supports following formats:
     * - rgba(255, 255, 255, 1)
     * - rgba(255, 255, 255, 0.5)
     * - rgba(255, 255, 255, .5)
     * - rgba(100%, 100%, 100%, 0.5)
     * - rgba(255 255 255 / 0.5) - CSS Color Level 4 syntax
     *
     * @param string $value The RGBA color string to validate
     * @return bool 
     */
    public static function rgbaColor(string $value): bool
    {
        $classicPattern = '/^rgba\(\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . ',\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . ',\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . ',\s*'
            . '(0|1|0?\.\d+|\.\d+|1\.0|100%|\d{1,2}%)\s*\)$/i';

        $css4Pattern = '/^rgba\(\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s+'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s+'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . '\/\s*'
            . '(0|1|0?\.\d+|\.\d+|1\.0|100%|\d{1,2}%)\s*\)$/i';

        return preg_match($classicPattern, $value) === 1 || preg_match($css4Pattern, $value) === 1;
    }

    /**
     * Validates HSL color format.
     * 
     * Supports:
     * - hsl(360, 100%, 50%)
     * - hsl(360deg, 100%, 50%) - with explicit degrees
     * - hsl(360 100% 50%) - CSS Color Level 4 syntax
     * 
     * @param string $value The HSL color string to validate
     * @return bool
     */
    public static function hslColor(string $value): bool
    {
        // Classic format: hsl(360, 100%, 50%)
        $classic_pattern = '/^hsl\(\s*'
            . '(360|3[0-5]\d|[12]?\d{1,2})(deg|grad|rad|turn)?\s*'
            . ',\s*'
            . '(100|\d{1,2})%\s*'
            . ',\s*'
            . '(100|\d{1,2})%\s*\)$/i';

        // CSS4 format: hsl(360 100% 50%)
        $css4_pattern = '/^hsl\(\s*'
            . '(360|3[0-5]\d|[12]?\d{1,2})(deg|grad|rad|turn)?\s+'
            . '(100|\d{1,2})%\s+'
            . '(100|\d{1,2})%\s*\)$/i';

        return preg_match($classic_pattern, $value) || preg_match($css4_pattern, $value);
    }

    /**
     * Validates HSLA color format with transparency.
     * 
     * Supports:
     * - hsla(360, 100%, 50%, 0.5)
     * - hsla(360deg, 100%, 50%, 50%) - with explicit degrees
     * - hsla(360 100% 50% / 0.5) - CSS Color Level 4 syntax
     * 
     * @param string $value The HSLA color string to validate
     * @return bool Returns true if valid HSLA format, false otherwise
     */
    public static function hslaColor(string $value): bool
    {
        // Classic format: hsla(360, 100%, 50%, 0.5)
        $classic_pattern = '/^hsla\(\s*'
            . '(360|3[0-5]\d|[12]?\d{1,2})(deg|grad|rad|turn)?\s*'
            . ',\s*'
            . '(100|\d{1,2})%\s*'
            . ',\s*'
            . '(100|\d{1,2})%\s*'
            . ',\s*'
            . '(0|1|0?\.\d+|1\.0|100%|\d{1,2}%)\s*\)$/i';

        // CSS4 format: hsla(360 100% 50% / 0.5)
        $css4_pattern = '/^hsla\(\s*'
            . '(360|3[0-5]\d|[12]?\d{1,2})(deg|grad|rad|turn)?\s+'
            . '(100|\d{1,2})%\s+'
            . '(100|\d{1,2})%\s*'
            . '\/\s*'
            . '(0|1|0?\.\d+|1\.0|100%|\d{1,2}%)\s*\)$/i';

        return preg_match($classic_pattern, $value) || preg_match($css4_pattern, $value);
    }

    /**
     * Validates any CSS color format (HEX, RGB, RGBA, HSL, HSLA etc.)
     * 
     * @param string $value The color string to validate
     * @return bool
     */
    public static function cssColor(string $value): bool
    {
        return self::hexColor($value)
            || self::rgbColor($value)
            || self::rgbaColor($value)
            || self::hslColor($value)
            || self::hslaColor($value);
    }

    /**
     * Checks if a string contains only Latin letters (with optional spaces, numbers, and punctuation).
     *
     * @param string $value The string to check.
     * @param bool $allowSpaces Whether to allow spaces (default: false)
     * @param bool $allowNumbers Whether to allow numbers (default: false)
     * @param bool $allowPunctuation Whether to allow punctuation (default: false)
     * @return bool
     */
    public static function latin(
        string $value,
        bool $allowSpaces = false,
        bool $allowNumbers = false,
        bool $allowPunctuation = false
    ): bool {
        $pattern = '/^[a-zA-Z';

        if ($allowSpaces) {
            $pattern .= '\s';
        }

        if ($allowNumbers) {
            $pattern .= '0-9';
        }

        if ($allowPunctuation) {
            $pattern .= '.,!?;:()\'"\-–—';
        }

        $pattern .= ']+$/';

        return preg_match($pattern, $value) === 1;
    }

    /**
     * Checks if a number is positive (greater than zero).
     *
     * @param int|float $number The number to check.
     * @return bool
     */
    public static function positiveNumber(int|float $number): bool
    {
        return is_numeric($number) && $number > 0;
    }

    /**
     * Checks if a number is negative (less than zero).
     *
     * @param int|float $number The number to check.
     * @return bool
     */
    public static function negativeNumber(int|float $number): bool
    {
        return is_numeric($number) && $number < 0;
    }

    /**
     * Checks if a number is even.
     *
     * @param int $number The number to check.
     * @return bool
     */
    public static function even(int $number): bool
    {
        return $number % 2 === 0;
    }

    /**
     * Checks if a number is odd.
     *
     * @param int $number The number to check.
     * @return bool
     */
    public static function odd(int $number): bool
    {
        return !self::even($number);
    }

    /**
     * Checks if a year is a leap year.
     *
     * @param int $year The year to check.
     * @return bool
     */
    public static function leapYear(int $year): bool
    {
        if ($year <= 0) {
            return false;
        }

        return ($year % 4 === 0 && $year % 100 !== 0) ||
            ($year % 400 === 0);
    }

    /**
     * Checks if a date is in the future (compared to current time).
     *
     * @param string $date The date in format Y-m-d.
     * @return bool
     */
    public static function futureDate(string $date): bool
    {
        try {
            $dateTime = new DateTime($date);
        } catch (\Exception $e) {
            return false;
        }

        if ($dateTime->format('Y-m-d') !== $date) {
            return false;
        }

        return $dateTime > new DateTime();
    }

    /**
     * Checks if a date is in the past (compared to current time).
     *
     * @param string $date The date in format Y-m-d.
     * @return bool
     */
    public static function pastDate(string $date): bool
    {
        try {
            $dateTime = new DateTime($date);
        } catch (\Exception $e) {
            return false;
        }

        if ($dateTime->format('Y-m-d') !== $date) {
            return false;
        }

        return $dateTime < new DateTime();
    }

    /**
     * Checks if a date is today.
     *
     * @param string $date The date in format Y-m-d.
     * @return bool
     */
    public static function today(string $date): bool
    {
        try {
            $dateTime = new DateTime($date);
        } catch (\Exception $e) {
            return false;
        }

        $now = new DateTime();
        return $dateTime->format('Y-m-d') === $now->format('Y-m-d');
    }

    /**
     * Checks the password complexity:
     * - Minimum of 8 characters
     * - At least 1 uppercase letter
     * - At least 1 lowercase letter
     * - At least 1 digit
     * - At least 1 special character
     * - Cyrillic alphabet can be included (optional)
     *
     * @param string $password Password for verification.
     * @param bool $allowCyrillic To allow Cyrillic (true/false).
     * @return bool
     */
    public static function strongPassword(
        string $password,
        bool $allowCyrillic = true
    ): bool {
        if (mb_strlen($password) < 8) {
            return false;
        }

        if (!$allowCyrillic && preg_match('/[^\x20-\x7F]/', $password)) {
            return false;
        }

        if (!preg_match('/[A-ZА-ЯЁ]/u', $password)) {
            return false;
        }

        if (!preg_match('/[a-zа-яё]/u', $password)) {
            return false;
        }

        if (!preg_match('/[0-9]/', $password)) {
            return false;
        }

        if (!preg_match('/[^A-Za-z0-9А-Яа-яЁё\s]/u', $password)) {
            return false;
        }

        return true;
    }

    /**
     * Checks if a string is a palindrome (reads the same backward).
     *
     * @param string $value The string to check.
     * @return bool
     */
    public static function palindrome(string $value): bool
    {
        $cleaned = mb_strtolower(preg_replace('/[^\p{L}\p{N}]/u', '', $value));
        $reversed = implode('', array_reverse(mb_str_split($cleaned)));

        return $cleaned !== '' && $cleaned === $reversed;
    }

    /**
     * Checks if a string is a valid Roman numeral.
     *
     * @param string $value The string to validate.
     * @param bool $allowLowercase Whether to allow lowercase roman numerals
     * @return bool
     */
    public static function romanNumeral(
        string $value,
        bool $allowLowercase = false
    ): bool {
        if ($value === '') {
            return false;
        }

        $pattern = '/^M{0,3}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})$/';

        if ($allowLowercase) {
            $pattern .= 'i';
        }

        return preg_match($pattern, $value) === 1;
    }

    /**
     * Checks if a string is a valid MAC address.
     * Supports formats: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXX.XXXX.XXXX
     *
     * @param string $mac The MAC address to validate.
     * @return bool
     */
    public static function macAddress(string $mac): bool
    {
        if (preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $mac)) {
            return true;
        }

        if (preg_match('/^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$/', $mac)) {
            return true;
        }

        return false;
    }

    /**
     * Checks if a string is a valid JSON.
     *
     * @param string $json The JSON string to validate
     * @param bool $allowScalar Whether to allow scalar values (null, numbers, strings, booleans)
     * @return bool
     */
    public static function json(
        string $json,
        bool $allowScalar = false
    ): bool {
        try {
            $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

            if ($allowScalar) {
                return !is_array($decoded);
            }

            return is_array($decoded);
        } catch (\JsonException $e) {
            return false;
        }
    }

    /**
     * Checks if a string contains emoji.
     *
     * @param string $text The string to check.
     * @return bool
     */
    public static function containsEmoji(string $text): bool
    {
        return preg_match(
            '/[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{2B00}-\x{2BFF}\x{FE00}-\x{FE0F}\x{1F1E6}-\x{1F1FF}]/u',
            $text
        ) === 1;
    }

    /**
     * Checks if a string is a valid Bitcoin address.
     * Supports legacy (P2PKH), SegWit (P2SH), and Bech32 formats.
     *
     * @param string $address The Bitcoin address to validate.
     * @return bool
     */
    public static function bitcoinAddress(string $address): bool
    {
        // Legacy P2PKH (1...)
        if (preg_match('/^1[a-km-zA-HJ-NP-Z1-9]{25,34}$/', $address)) {
            return true;
        }

        // SegWit P2SH (3...)
        if (preg_match('/^3[a-km-zA-HJ-NP-Z1-9]{25,34}$/', $address)) {
            return true;
        }

        // Bech32 (bc1...)
        if (preg_match('/^bc1[a-z0-9]{25,90}$/i', $address)) {
            return true;
        }

        return false;
    }

    /**
     * Checks if the value length does not exceed the specified maximum length
     * 
     * @param mixed $value - The value to validate
     * @param int $length - Maximum allowed length
     * @return bool
     */
    public static function maxLength(mixed $value, int $length): bool
    {
        if ($value === null) {
            return true;
        }

        if (is_array($value)) {
            return count($value) <= $length;
        }

        return mb_strlen(strval($value), 'UTF-8') <= $length;
    }

    /**
     * Checks if the value length meets or exceeds the specified minimum length
     * 
     * @param mixed $value - The value to validate
     * @param int $length - Minimum required length
     * @return bool
     */
    public static function minLength(mixed $value, int $length): bool
    {
        if ($value === null) {
            return false;
        }

        if (is_array($value)) {
            return count($value) >= $length;
        }

        return mb_strlen(strval($value), 'UTF-8') >= $length;
    }

    /**
     * Validates if a string is a properly formatted slug (URL-friendly string)
     * 
     * @param string $slug The string to validate as a slug
     * @param string|array $separators Allowed separators (default: ['-', '_'])
     * @param int $maxLength Maximum allowed length (0 for no limit)
     * @return bool
     */
    public static function slug(
        string $slug,
        string|array $separators = ['-', '_'],
        int $maxLength = 80
    ): bool {
        $separators = is_array($separators) ? $separators : [$separators];
        $separators = array_filter($separators);

        if ($maxLength > 0 && mb_strlen($slug) > $maxLength) {
            return false;
        }

        $separatorsPattern = '';

        foreach ($separators as $sep) {
            $separatorsPattern .= preg_quote($sep, '/');
        }

        $pattern = '/^[a-z0-9' . $separatorsPattern . ']+$/';
        if (!preg_match($pattern, $slug)) {
            return false;
        }

        if (count($separators) > 1) {
            $separatorsPairs = [];
            foreach ($separators as $sep1) {
                foreach ($separators as $sep2) {
                    if ($sep1 !== $sep2) {
                        $separatorsPairs[] = preg_quote($sep1, '/') . preg_quote($sep2, '/');
                    }
                }
            }
            $mixedPattern = '/(' . implode('|', $separatorsPairs) . ')/';
            if (preg_match($mixedPattern, $slug)) {
                return false;
            }
        }

        foreach ($separators as $sep) {
            if (str_contains($slug, $sep . $sep)) {
                return false;
            }

            if (str_starts_with($slug, $sep) || str_ends_with($slug, $sep)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Quick check for threats in content
     * 
     * @param string $content Content to check
     * @param int $maxLength Maximum safe content length (default 100000)
     * @return bool
     */
    public static function dangerous(
        string $content,
        int $maxLength = 100000
    ): bool {
        return self::nullBytes($content)
            || self::unicodeBomb($content)
            || self::longLines($content)
            || strlen($content) > $maxLength;
    }

    /**
     * Check if content is safe (reverse of dangerous())
     * 
     * @param string $content Content to check
     * @param int $maxLength Maximum safe content length (default 100000)
     * @return bool
     */
    public static function safeChars(
        string $content,
        int $maxLength = 100000
    ): bool {
        return !self::dangerous($content, $maxLength);
    }

    /**
     * Check for null bytes and control characters
     * 
     * @param string $content Content to check
     * @return bool
     */
    public static function nullBytes(string $content): bool
    {
        return preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $content) === 1;
    }

    /**
     * Check if content is free from null bytes and control characters (reverse of nullBytes())
     * 
     * @param string $content Content to check
     * @return bool
     */
    public static function noNullBytes(string $content): bool
    {
        return !self::nullBytes($content);
    }

    /**
     * Check for dangerous protocols
     * 
     * @param string $content Content to check
     * @return bool
     */
    public static function dangerousProtocols(string $content): bool
    {
        $patterns = [
            '/php:\/\/(filter|input|glob|expect|zip|data|phar|temp|memory)/i',
            '/phar:\/\//i',
            '/\b(file|ftp|gopher|jar|ldap|ssh2?|telnet|dict|zlib|ogg|rar|expect):\/\//i',
            '/data:(text\/(html|javascript|vbscript)|application\/(x-php|javascript))/i',
            '/\b(javascript|vbscript|data|mocha|livescript):/i',
            '/<!ENTITY\s+/i',
            '/<!DOCTYPE\s+/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if content uses only safe protocols (reverse of dangerousProtocols())
     * 
     * @param string $content Content to check
     * @return bool
     */
    public static function safeProtocols(string $content): bool
    {
        return !self::dangerousProtocols($content);
    }

    /**
     * Detect unicode bombs (excessive encoding ratio)
     * 
     * @param string $content Content to check
     * @param bool $searchEverywhere Search everywhere
     * @return bool
     */
    public static function unicodeBomb(
        string $content,
        bool $searchEverywhere = false
    ): bool {
        if ($searchEverywhere) {
            return strpos($content, "\xEF\xBB\xBF") !== false;
        }

        return substr($content, 0, 3) === "\xEF\xBB\xBF";
    }

    /**
     * Check if content is free from unicode BOM (reverse of unicodeBomb())
     * 
     * @param string $content Content to check
     * @param bool $searchEverywhere Search everywhere
     * @return bool
     */
    public static function noUnicodeBomb(
        string $content,
        bool $searchEverywhere = false
    ): bool {
        return !self::unicodeBomb($content, $searchEverywhere);
    }

    /**
     * Check for excessively long lines
     * 
     * @param string $content Content to check
     * @param int $detectLength Detection threshold (default 10000)
     * @return bool
     */
    public static function longLines(string $content, int $detectLength = 10000): bool
    {
        if ($detectLength <= 0) {
            return false;
        }

        $lines = explode("\n", $content);

        foreach ($lines as $line) {
            $line = rtrim($line, "\r");
            if (mb_strlen($line, 'UTF-8') >= $detectLength) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if all lines are within acceptable length (reverse of longLines())
     * 
     * @param string $content Content to check
     * @param int $maxLength Maximum allowed line length (default 10000)
     * @return bool
     */
    public static function reasonableLineLength(string $content, int $maxLength = 10000): bool
    {
        return !self::longLines($content, $maxLength);
    }
}
