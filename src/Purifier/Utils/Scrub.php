<?php

namespace Cleup\Guard\Purifier\Utils;

class Scrub
{
    /**
     * Escapes special characters in a string for safe HTML output
     * 
     * @param string $input The input string to be escaped
     * @param string $chaset Charset
     * @return string
     */
    public static function escape(string $input, $chaset = 'UTF-8'): string
    {
        return htmlspecialchars($input, ENT_QUOTES, $chaset);
    }

    /**
     * Sanitizes email address
     * 
     * @param string $input Input email address
     * @return string 
     */
    public static function email(string $input): string
    {
        $input = trim($input);
        $filtered = filter_var($input, FILTER_SANITIZE_EMAIL);

        return filter_var($filtered, FILTER_VALIDATE_EMAIL) !== false
            ? $filtered
            : '';
    }

    /**
     * Converts special characters to HTML entities and preserves UTF-8
     * 
     * @param string $input Input string
     * @param string $encoding Character encoding
     * @return string 
     */
    public static function encode(string $input, string $encoding = 'UTF-8'): string
    {
        return htmlentities($input, ENT_QUOTES | ENT_SUBSTITUTE, $encoding);
    }

    /**
     * Validates whether a string is a properly formatted URL
     * 
     * @param string $url The string to validate as a URL
     * @return string|false
     */
    public static function url(string $url): string
    {
        $filter = filter_var($url, FILTER_VALIDATE_URL);

        return $filter !== false ? $filter : '';
    }

    /**
     * Removes all non-digit characters from input
     * 
     * @param mixed $input Input value
     * @return string Digits only
     */
    public static function digits(mixed $input): string
    {
        return preg_replace('/[^0-9]/', '', static::toString($input));
    }

    /**
     * Strips all whitespace characters from string
     * 
     * @param string $input Input string
     * @return string String without whitespace
     */
    public static function stripWhitespace(string $input): string
    {
        return preg_replace('/\s+/', '', $input);
    }

    /**
     * Normalizes string - trims, removes duplicate spaces, normalizes line breaks
     * 
     * @param string $input Input string
     * @return string Normalized string
     */
    public static function normalizeString(string $input): string
    {
        $input = trim($input);
        $input = preg_replace('/\s+/', ' ', $input); // Multiple spaces to single
        $input = preg_replace('/\R/u', "\n", $input); // Normalize line breaks

        return $input;
    }

    /**
     * Converts string to slug (URL-friendly format)
     * 
     * @param string $slug Input slug
     * @param string|array $separators Allowed separators (default: ['-', '_'])
     * @param int $maxLength Maximum length
     * @return string 
     */
    public static function slug(string $slug, string|array $separators = ['-', '_'], int $maxLength = 80): string
    {
        $separators = is_array($separators) ? $separators : [$separators];
        $separators = array_unique(array_filter($separators, 'strlen'));
        if (empty($separators)) {
            $separators = ['-'];
        }

        $slug = mb_strtolower($slug);
        $allowedSeps = preg_quote(implode('', $separators), '/');
        $slug = preg_replace('/[\s' . ($allowedSeps ? '|[^\w' . $allowedSeps . ']' : '') . ']+/u', $separators[0], $slug);
        $allowed = 'a-z0-9' . $allowedSeps;
        $slug = preg_replace("/[^{$allowed}]/u", '', $slug);

        foreach ($separators as $sep) {
            $quoted = preg_quote($sep, '/');
            $slug = preg_replace("/{$quoted}{2,}/", $sep, $slug);
        }

        if (count($separators) > 1) {
            $pattern = '/([' . preg_quote(implode('', $separators), '/') . '])([' . preg_quote(implode('', $separators), '/') . '])/';
            while (preg_match($pattern, $slug)) {
                $slug = preg_replace_callback(
                    $pattern,
                    function ($m) use ($separators) {
                        return in_array($m[1], $separators) ? $m[1] : $m[2];
                    },
                    $slug,
                    1
                );
            }
        }

        $trimPattern = '/^[' . $allowedSeps . ']+|[' . $allowedSeps . ']+$/';
        $slug = preg_replace($trimPattern, '', $slug);

        if ($maxLength > 0) {
            $slug = mb_substr($slug, 0, $maxLength);
            $slug = preg_replace('/[' . $allowedSeps . ']+$/', '', $slug);
        }

        return $slug;
    }

    /**
     * Transliterates Cyrillic text to Latin
     * 
     * @param string $str Input string with Cyrillic characters
     * @param string $separator Allowed separator ('_', '-', or 'both' for either)
     * @param bool $upper Convert result to uppercase (false for lowercase)
     * @return string
     */
    public static function translitCyrillic(
        string $str,
        string $separator = 'both',
        bool $upper = false,
    ): string {
        $useUnderscore = $separator === 'both' || $separator === '_';
        $useHyphen = $separator === 'both' || $separator === '-';

        $translitMap = [
            'а' => 'a',
            'б' => 'b',
            'в' => 'v',
            'г' => 'g',
            'д' => 'd',
            'е' => 'e',
            'ё' => 'e',
            'ж' => 'zh',
            'з' => 'z',
            'и' => 'i',
            'й' => 'y',
            'к' => 'k',
            'л' => 'l',
            'м' => 'm',
            'н' => 'n',
            'о' => 'o',
            'п' => 'p',
            'р' => 'r',
            'с' => 's',
            'т' => 't',
            'у' => 'u',
            'ф' => 'f',
            'х' => 'kh',
            'ц' => 'ts',
            'ч' => 'ch',
            'ш' => 'sh',
            'щ' => 'sch',
            'ъ' => '',
            'ы' => 'y',
            'ь' => '',
            'э' => 'e',
            'ю' => 'yu',
            'я' => 'ya',
            'А' => 'A',
            'Б' => 'B',
            'В' => 'V',
            'Г' => 'G',
            'Д' => 'D',
            'Е' => 'E',
            'Ё' => 'E',
            'Ж' => 'Zh',
            'З' => 'Z',
            'И' => 'I',
            'Й' => 'Y',
            'К' => 'K',
            'Л' => 'L',
            'М' => 'M',
            'Н' => 'N',
            'О' => 'O',
            'П' => 'P',
            'Р' => 'R',
            'С' => 'S',
            'Т' => 'T',
            'У' => 'U',
            'Ф' => 'F',
            'Х' => 'Kh',
            'Ц' => 'Ts',
            'Ч' => 'Ch',
            'Ш' => 'Sh',
            'Щ' => 'Sch',
            'Ъ' => '',
            'Ы' => 'Y',
            'Ь' => '',
            'Э' => 'E',
            'Ю' => 'Yu',
            'Я' => 'Ya'
        ];

        $str = str_replace(
            ['Ж', 'ж', 'Х', 'х', 'Ц', 'ц', 'Ч', 'ч', 'Ш', 'ш', 'Щ', 'щ', 'Ю', 'ю', 'Я', 'я'],
            ['Zh', 'zh', 'Kh', 'kh', 'Ts', 'ts', 'Ch', 'ch', 'Sh', 'sh', 'Sch', 'sch', 'Yu', 'yu', 'Ya', 'ya'],
            $str
        );

        $str = strtr(mb_strtoupper($str), $translitMap);
        $allowed = 'A-Z0-9';

        if ($useUnderscore) $allowed .= '_';
        if ($useHyphen) $allowed .= '-';

        $str = preg_replace_callback(
            "/[^{$allowed}]/",
            function ($matches) use ($useHyphen) {
                return $useHyphen ? '-' : '_';
            },
            $str
        );


        if ($useUnderscore && $useHyphen) {
            $str = preg_replace(['/_{2,}/', '/-{2,}/'], ['_', '-'], $str);
        } else {
            $sep = $useHyphen ? '-' : '_';
            $str = preg_replace("/{$sep}{2,}/", $sep, $str);
        }

        $trimPattern = [];

        if ($useUnderscore) $trimPattern[] = '_';
        if ($useHyphen) $trimPattern[] = '-';

        $trimPattern = '/^[' . implode('', $trimPattern) . ']+|[' . implode('', $trimPattern) . ']+$/';
        $str = preg_replace($trimPattern, '', $str);
        $str = str_replace(['-_', '_-'], '-', $str);

        return $upper ? $str : mb_strtolower($str);
    }

    /**
     * Filters input value and returns it as integer or float if numeric.
     * 
     * @param mixed $input The input value to be filtered
     * @return int|float
     */
    public static function toNumeric(mixed $input): int|float
    {
        $input = static::toString($input);

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
     * Filters the input value and returns it as a string
     * 
     * @param mixed $input The input value to be filtered
     * @return string
     */
    public static function toString(mixed $input): string
    {
        if (is_string($input))
            return $input;

        if (is_int($input) || is_float($input))
            return (string)$input;

        if (is_bool($input))
            return $input ? 'true' : 'false';

        if (is_null($input))
            return '';

        if (is_array($input))
            return json_encode($input, JSON_UNESCAPED_UNICODE);

        if (is_object($input)) {
            if (method_exists($input, '__toString'))
                return (string)$input;

            if ($input instanceof \JsonSerializable)
                return json_encode($input, JSON_UNESCAPED_UNICODE);

            return json_encode((array)$input, JSON_UNESCAPED_UNICODE);
        }

        if (is_resource($input))
            return '';

        return '';
    }


    /**
     * Cleans the input text by removing all HTML tags, special characters, and emojis,
     * leaving only plain text (letters in any language), numbers, spaces, and basic punctuation.
     *
     * @param string $text The input text to be cleaned
     * @return string
     */
    public static function text(string $text): string
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
        $text = static::text($text);
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

    /**
     * @see Scrub::url()
     * @deprecated since version 1.0.6 Use Scrub::url() instead.
     * @param string $text The input text to be cleaned
     * @return string
     */
    public static function filterUrl(string $url): string
    {
        return static::url($url);
    }

    /**
     * @see Scrub::text()
     * @deprecated since version 1.0.6 Use Scrub::text() instead.
     * @param string $text The input text to be cleaned
     * @return string
     */
    public static function filterText(string $url): mixed
    {
        return static::text($url);
    }
}
