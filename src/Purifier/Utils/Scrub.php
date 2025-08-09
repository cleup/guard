<?php

namespace Cleup\Guard\Purifier\Utils;

class Scrub
{
    /**
     * Escapes special characters in a string for safe HTML output
     * 
     * @param string $input The input string to be escaped
     * @return string
     */
    public static function escape(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Validates whether a string is a properly formatted URL
     * 
     * @param string $url The string to validate as a URL
     * @return string|false
     */
    public static function filterUrl(string $url): mixed
    {
        return filter_var($url, FILTER_VALIDATE_URL);
    }

    /**
     * Filters input value and returns it as integer or float if numeric.
     * 
     * @param mixed $input The input value to be filtered
     * @return int|float
     */
    public static function filterNumeric(mixed $input): int|float
    {
        if (is_numeric($input)) {
            if (is_float($input + 0) || strpos($input, '.') !== false || stripos($input, 'e') !== false) {
                return (float)$input;
            } else {
                return (int)$input;
            }
        }

        return 0;
    }

    /**
     * Cleans the input text by removing all HTML tags, special characters, and emojis,
     * leaving only plain text (letters in any language), numbers, spaces, and basic punctuation.
     *
     * @param string $text The input text to be cleaned
     * @return string
     */
    public static function filterText(string $text): string
    {
        // Remove emojis and smileys (Unicode ranges)
        $text = preg_replace('/[\x{1F600}-\x{1F64F}]/u', '', $text); // Smileys & emoticons
        $text = preg_replace('/[\x{1F300}-\x{1F5FF}]/u', '', $text); // Symbols & pictographs
        $text = preg_replace('/[\x{1F680}-\x{1F6FF}]/u', '', $text); // Transport & map symbols
        $text = preg_replace('/[\x{2600}-\x{26FF}]/u', '', $text);   // Miscellaneous symbols
        $text = preg_replace('/[\x{2700}-\x{27BF}]/u', '', $text);   // Dingbats

        // Remove HTML and PHP tags
        $text = strip_tags($text);

        // Convert HTML entities to their corresponding characters
        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $text = preg_replace('/[^\p{L}\p{N}\s.,!?;:()\'"\-–—\/]/u', '', $text);

        // Normalize whitespace
        $text = preg_replace('/\s+/', ' ', $text);
        $text = trim($text);

        return $text;
    }

    /**
     * Truncates text to specified length with optional affixes
     * 
     * @param string $text Input text to truncate
     * @param int|array $characters Max length or [offset, length] pair
     * @param string $after Suffix if truncated
     * @param string $before Prefix if truncated
     * @param bool $reverse Truncate from end if true
     * @return string Processed text
     */
    public static function truncate(
        string $text,
        int|array $characters = 15,
        string $after = "",
        string $before = "",
        bool $reverse = false
    ): string {
        $text = static::filterText($text);
        $length = mb_strlen($text);

        // Extract offset and length from array or use defaults
        [$offset, $characters] = is_array($characters)
            ? [$characters[0] ?? 0, $characters[1] ?? 15]
            : [0, $characters];

        if ($length <= $characters) {
            return trim($text);
        }

        $text = match (true) {
            $reverse && $offset => mb_substr(mb_substr($text, 0, -$offset), -$characters),
            $reverse => mb_substr($text, -$characters),
            default => mb_substr($text, $offset, $characters)
        };

        return ($length > $characters ? $before : '') . trim($text) . ($length > $characters ? $after : '');
    }
}
