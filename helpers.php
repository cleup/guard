<?php

use Cleup\Guard\Purifier\Utils\Scrub;
use Cleup\Guard\Purifier\Utils\Valid;

if (!function_exists('escape')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Scrub::escape()
     */
    function escape(string $input): string
    {
        return Scrub::escape($input);
    }
}

if (!function_exists('filter_url')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Scrub::filterUrl()
     */
    function filter_url(string $input): mixed
    {
        return Scrub::filterUrl($input);
    }
}

if (!function_exists('filter_text')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Scrub::filterText()
     */
    function filter_text(string $input): string
    {
        return Scrub::filterText($input);
    }
}

if (!function_exists('truncate')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Scrub::truncate()
     */
    function truncate(
        string $text,
        int|array $characters = 15,
        string $after = "",
        string $before = "",
        bool $reverse = false
    ): string {
        return Scrub::truncate(
            $text,
            $characters,
            $after,
            $before,
            $reverse
        );
    }
}

if (!function_exists('is_email')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::email()
     */
    function is_email(string $email): bool
    {
        return Valid::email($email);
    }
}

if (!function_exists('is_url')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::url()
     */
    function is_url(string $url): bool
    {
        return Valid::url($url);
    }
}

if (!function_exists('is_domain')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::domain()
     */
    function is_domain(string $domain): bool
    {
        return Valid::domain($domain);
    }
}

if (!function_exists('is_ip')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::ip()
     */
    function is_ip(string $ip): bool
    {
        return Valid::ip($ip);
    }
}

if (!function_exists('is_phone')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::phone()
     */
    function is_phone(string $phone): bool
    {
        return Valid::phone($phone);
    }
}

if (!function_exists('is_date_format')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::dateFormat()
     */
    function is_date_format(string $date, string $format = 'Y-m-d'): bool
    {
        return Valid::dateFormat($date, $format);
    }
}

if (!function_exists('is_not_empty')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::notEmpty()
     */
    function is_not_empty(string $value): bool
    {
        return Valid::notEmpty($value);
    }
}

if (!function_exists('is_hex_color')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::hexColor()
     */
    function is_hex_color(string $value): bool
    {
        return Valid::hexColor($value);
    }
}

if (!function_exists('is_rgba_color')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::rgbaColor()
     */
    function is_rgba_color(string $value): bool
    {
        return Valid::rgbaColor($value);
    }
}

if (!function_exists('is_rgb_color')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::rgbColor()
     */
    function is_rgb_color(string $value): bool
    {
        return Valid::rgbColor($value);
    }
}

if (!function_exists('is_hsl_color')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::hslColor()
     */
    function is_hsl_color(string $value): bool
    {
        return Valid::hslColor($value);
    }
}

if (!function_exists('is_hsla_color')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::hslaColor()
     */
    function is_hsla_color(string $value): bool
    {
        return Valid::hslaColor($value);
    }
}

if (!function_exists('is_css_color')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::cssColor()
     */
    function is_css_color(string $value): bool
    {
        return Valid::cssColor($value);
    }
}

if (!function_exists('is_latin')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::latin()
     */
    function is_latin(string $value): bool
    {
        return Valid::latin($value);
    }
}

if (!function_exists('is_positive_number')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::positiveNumber()
     */
    function is_positive_number($number): bool
    {
        return Valid::positiveNumber($number);
    }
}

if (!function_exists('is_negative_number')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::negativeNumber()
     */
    function is_negative_number($number): bool
    {
        return Valid::negativeNumber($number);
    }
}

if (!function_exists('is_even')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::even()
     */
    function is_even(int $number): bool
    {
        return Valid::even($number);
    }
}

if (!function_exists('is_odd')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::odd()
     */
    function is_odd(int $number): bool
    {
        return Valid::odd($number);
    }
}

if (!function_exists('is_leap_year')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::leapYear()
     */
    function is_leap_year(int $year): bool
    {
        return Valid::leapYear($year);
    }
}

if (!function_exists('is_future_date')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::futureDate()
     */
    function is_future_date(string $date): bool
    {
        return Valid::futureDate($date);
    }
}

if (!function_exists('is_past_date')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::pastDate()
     */
    function is_past_date(string $date): bool
    {
        return Valid::pastDate($date);
    }
}

if (!function_exists('is_today')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::today()
     */
    function is_today(string $date): bool
    {
        return Valid::today($date);
    }
}

if (!function_exists('is_strong_password')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::strongPassword()
     */
    function is_strong_password(string $password, bool $allowCyrillic = true): bool
    {
        return Valid::strongPassword($password, $allowCyrillic);
    }
}

if (!function_exists('is_palindrome')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::palindrome()
     */
    function is_palindrome(string $value): bool
    {
        return Valid::palindrome($value);
    }
}

if (!function_exists('is_roman_numeral')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::romanNumeral()
     */
    function is_roman_numeral(string $value): bool
    {
        return Valid::romanNumeral($value);
    }
}

if (!function_exists('is_mac_address')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::macAddress()
     */
    function is_mac_address(string $mac): bool
    {
        return Valid::macAddress($mac);
    }
}

if (!function_exists('is_json')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::json()
     */
    function is_json(string $json): bool
    {
        return Valid::json($json);
    }
}

if (!function_exists('contains_emoji')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::containsEmoji()
     */
    function contains_emoji(string $text): bool
    {
        return Valid::containsEmoji($text);
    }
}

if (!function_exists('is_bitcoin_address')) {
    /**
     * @see Cleup\Guard\Purifier\Utils\Valid::bitcoinAddress()
     */
    function is_bitcoin_address(string $address): bool
    {
        return Valid::bitcoinAddress($address);
    }
}
