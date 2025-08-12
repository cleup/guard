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
     * @return bool
     */
    public static function url(string $url): bool
    {
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
        if (is_string($allowedHosts))
            $allowedHosts = [$allowedHosts];

        $parsed = parse_url($url);

        if (!isset($parsed['host'])) {
            return false;
        }

        $host = strtolower($parsed['host']);
        $allowedHosts = array_map('strtolower', $allowedHosts);

        foreach ($allowedHosts as $allowedHost) {
            if (
                $host === $allowedHost ||
                (str_ends_with($host, '.' . $allowedHost) && $host !== $allowedHost)
            ) {
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

        if (preg_match('//u', $domain)) {
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
     * Validates if string is a properly formatted IPv4 or IPv6 address.
     *
     * @param string $ip The IP address string to validate
     * @return bool
     */
    public static function ip(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
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
        $digitsOnly = preg_replace('/[^0-9]/', '', $phone);
        $digitLength = strlen($digitsOnly);
        $hasPlus = str_starts_with($phone, '+');

        if ($digitLength < 7 || ($hasPlus && $digitLength > 15) || (!$hasPlus && $digitLength > 11)) {
            return false;
        }

        if (preg_match('/^[01]+$/', $digitsOnly)) {
            return false;
        }

        if (preg_match('/(\d)\1{6,}/', $digitsOnly)) {
            return false;
        }

        if (preg_match('/^(\+7|7|8)/', $phone) && $digitLength !== 11) {
            return false;
        }

        $patterns = [
            // +CCC XXX XXX-XXXX
            '/^\+\d{1,3}(?:[ \-]?\d{2,5}){2,4}$/',

            // Russian (+7|8)
            '/^\+7[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}$/',
            '/^8[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}$/',
            '/^7\d{10}$/',

            // 7-11
            '/^\d{3}[\s\-]?\d{2}[\s\-]?\d{2}$/',             // 800 123-45
            '/^\(?\d{3,5}\)?[\s\-]?\d{2,4}[\s\-]?\d{2,4}$/', // (812) 123-45-67
            '/^\d{7,11}$/'                                   // 12345678901
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
     * Checks if string is not empty (after trimming whitespace).
     *
     * @param string $value The string to check
     * @return bool
     */
    public static function notEmpty(string $value): bool
    {
        return trim($value) !== '';
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
     * Validates RGBA color format with transparency.
     * 
     * Supports following formats:
     * - rgba(255, 255, 255, 1)
     * - rgba(255, 255, 255, 0.5)
     * - rgba(100%, 100%, 100%, 0.5)
     * - rgba(255 255 255 / 0.5) - CSS Color Level 4 syntax
     * - With optional spaces after commas
     *
     * @param string $value The RGBA color string to validate
     * @return bool 
     */
    public static function rgbaColor(string $value): bool
    {
        // Classic format: rgba(255, 255, 255, 0.5)
        $classicPattern = '/^rgba\(\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . ',\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . ',\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . ',\s*'
            . '(0|1|0?\.\d+|1\.0|100%|\d{1,2}%)\s*\)$/i';

        // CSS4 format: rgba(255 255 255 / 0.5)
        $css4Pattern = '/^rgba\(\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s+'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s+'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*'
            . '\/\s*'
            . '(0|1|0?\.\d+|1\.0|100%|\d{1,2}%)\s*\)$/i';

        return preg_match($classicPattern, $value) || preg_match($css4Pattern, $value);
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

        // CSS4 format: rgb(255 255 255)
        $css4Pattern = '/^rgb\(\s*'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s+'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s+'
            . '(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}|100%|\d{1,2}%)\s*\)$/i';

        return preg_match($classicPattern, $value) || preg_match($css4Pattern, $value);
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
     * Checks if a string contains only Latin letters (no Cyrillic or other alphabets).
     *
     * @param string $value The string to check.
     * @return bool
     */
    public static function latin(string $value): bool
    {
        return preg_match('/^[a-zA-Z]+$/', $value) === 1;
    }

    /**
     * Checks if a number is positive (greater than zero).
     *
     * @param int|float $number The number to check.
     * @return bool
     */
    public static function positiveNumber($number): bool
    {
        return $number > 0;
    }

    /**
     * Checks if a number is negative (less than zero).
     *
     * @param int|float $number The number to check.
     * @return bool
     */
    public static function negativeNumber($number): bool
    {
        return $number < 0;
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
        return ($year % 4 === 0 && $year % 100 !== 0) || ($year % 400 === 0);
    }

    /**
     * Checks if a date is in the future (compared to current time).
     *
     * @param string $date The date in format Y-m-d.
     * @return bool
     */
    public static function futureDate(string $date): bool
    {
        $dateTime = new DateTime($date);
        $now = new DateTime();
        return $dateTime > $now;
    }

    /**
     * Checks if a date is in the past (compared to current time).
     *
     * @param string $date The date in format Y-m-d.
     * @return bool
     */
    public static function pastDate(string $date): bool
    {
        return !self::futureDate($date);
    }

    /**
     * Checks if a date is today.
     *
     * @param string $date The date in format Y-m-d.
     * @return bool
     */
    public static function today(string $date): bool
    {
        $dateTime = new DateTime($date);
        $now = new DateTime();
        return $dateTime->format('Y-m-d') === $now->format('Y-m-d');
    }

    /**
     * Checks the password complexity:
     * - Minimum of 8 characters
     * - At least 1 letter (Latin or Cyrillic)
     * - At least 1 digit
     * - At least 1 special character
     * - Cyrillic alphabet can be included (optional)
     *
     * @param string $password Password for verification.
     * @param bool $allowCyrillic To allow Cyrillic (true/false).
     * @return bool
     */
    public static function strongPassword(string $password, bool $allowCyrillic = true): bool
    {
        if (strlen($password) < 8) {
            return false;
        }

        if (!$allowCyrillic && preg_match('/[^\x20-\x7F]/', $password)) {
            return false;
        }

        $hasLetter = $allowCyrillic
            ? preg_match('/[A-Za-zА-Яа-я]/u', $password)
            : preg_match('/[A-Za-z]/', $password);

        if (!$hasLetter) {
            return false;
        }

        if (!preg_match('/[0-9]/', $password)) {
            return false;
        }

        if (!preg_match('/[\W_]/u', $password)) {
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
        $cleaned = strtolower(preg_replace('/[^a-z0-9]/i', '', $value));
        return $cleaned === strrev($cleaned);
    }

    /**
     * Checks if a string is a valid Roman numeral.
     *
     * @param string $value The string to validate.
     * @return bool
     */
    public static function romanNumeral(string $value): bool
    {
        return preg_match('/^M{0,3}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})$/', $value) === 1;
    }

    /**
     * Checks if a string is a valid MAC address.
     *
     * @param string $mac The MAC address to validate.
     * @return bool
     */
    public static function macAddress(string $mac): bool
    {
        return preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $mac) === 1;
    }

    /**
     * Checks if a string is a valid JSON.
     *
     * @param string $json The JSON string to validate.
     * @return bool
     */
    public static function json(string $json): bool
    {
        json_decode($json);
        return json_last_error() === JSON_ERROR_NONE;
    }

    /**
     * Checks if a string contains emoji.
     *
     * @param string $text The string to check.
     * @return bool
     */
    public static function containsEmoji(string $text): bool
    {
        return preg_match('/[\x{1F600}-\x{1F64F}\x{1F300}-\x{1F5FF}\x{1F680}-\x{1F6FF}]/u', $text) === 1;
    }

    /**
     * Checks if a string is a valid Bitcoin address.
     *
     * @param string $address The Bitcoin address to validate.
     * @return bool
     */
    public static function bitcoinAddress(string $address): bool
    {
        return preg_match('/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/', $address) === 1;
    }

    /**
     * Checks if the value length does not exceed the specified maximum length
     * 
     * @param int|float|string $value - The value to validate (can be number or string)
     * @param int $length - Maximum allowed length
     * @return bool
     */
    public static function maxLength(int|float|string $value, int $length): bool
    {
        return mb_strlen(strval($value), 'UTF-8') <= $length;
    }

    /**
     * Checks if the value length meets or exceeds the specified minimum length
     * 
     * @param int|float|string $value - The value to validate (can be number or string)
     * @param int $length - Minimum required length
     * @return bool
     */
    public static function minLength(int|float|string $value, int $length): bool
    {
        return mb_strlen(strval($value), 'UTF-8') >= $length;
    }
}
