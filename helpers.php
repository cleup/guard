<?php

use Cleup\Guard\Purifier\Scrub;

if (!function_exists('escape')) {
    /**
     * Escapes special characters in a string for safe HTML output
     * 
     * @return string 
     */
    function escape(string $input): string
    {
        return Scrub::escape($input);
    }
}

if (!function_exists('filter_url')) {
    /**
     * Escapes special characters in a string for safe HTML output
     * 
     * @return string 
     */
    function filter_url(string $input): mixed
    {
        return Scrub::filterUrl($input);
    }
}

if (!function_exists('filter_text')) {
    /**
     * Clears invalid characters from a string.
     * 
     * @return string 
     */
    function filter_text(string $input): string
    {
        return Scrub::filterText($input);
    }
}

if (!function_exists('truncate')) {
    /**
     * Truncates text to specified length with optional affixes
     * 
     * @param string $text Input text to truncate
     * @param int|array $characters Max length or [offset, length] pair
     * @param string $after Suffix if truncated
     * @param string $before Prefix if truncated
     * @param bool $reverse Truncate from end if true
     * @return string
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
