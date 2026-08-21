<?php

namespace Cleup\Guard\Purifier\Utils;

class Scrub
{
    /**
     * Escapes special characters in a string for safe HTML output
     * 
     * @param string $input The input string to be escaped
     * @param ?string $charset Charset
     * @return string
     */
    public static function escape(
        string $input,
        ?string $charset = 'UTF-8'
    ): string {
        return htmlspecialchars($input, ENT_QUOTES, $charset);
    }

    /**
     * Sanitizes email address
     * 
     * @param string $input Input email address
     * @return ?string 
     */
    public static function email(string $input): ?string
    {
        $input = trim($input);
        $filtered = filter_var($input, FILTER_SANITIZE_EMAIL);

        if (mb_strlen($filtered, 'UTF-8') > 254) {
            return null;
        }

        if (preg_match('/\s/', $filtered)) {
            return null;
        }

        if (filter_var($filtered, FILTER_VALIDATE_EMAIL)) {
            return strtolower($filtered);
        }

        return null;
    }

    /**
     * Converts special characters to HTML entities and preserves UTF-8
     * 
     * @param string $input Input string
     * @param string $encoding Character encoding
     * @return string 
     */
    public static function encode(
        string $input,
        string $encoding = 'UTF-8'
    ): string {
        return htmlentities(
            $input,
            ENT_QUOTES | ENT_SUBSTITUTE,
            $encoding
        );
    }

    /**
     * Validates whether a string is a properly formatted URL
     * 
     * @param string $url The string to validate as a URL
     * @return ?string
     */
    public static function url(string $url): ?string
    {
        $url = trim($url);

        $filtered = filter_var($url, FILTER_SANITIZE_URL);
        $validated = filter_var($filtered, FILTER_VALIDATE_URL);

        if ($validated === false) {
            return null;
        }

        return $validated;
    }

    /**
     * Removes all non-digit characters from input
     * 
     * @param mixed $input Input value
     * @return string
     */
    public static function digits(mixed $input): string
    {
        return preg_replace('/[^0-9]/', '', static::toString($input));
    }

    /**
     * Strips all whitespace characters from string
     * 
     * @param string $input Input string
     * @return string
     */
    public static function stripWhitespace(string $input): string
    {
        return preg_replace('/\s+/', '', $input);
    }

    /**
     * Normalizes string - trims, removes duplicate spaces, normalizes line breaks
     * 
     * @param string $input Input string
     * @return string
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
    public static function slug(
        string $slug,
        string|array $separators = ['-', '_'],
        int $maxLength = 80
    ): string {
        $separators = is_array($separators) ? $separators : [$separators];
        $separators = array_unique(array_filter($separators, 'strlen'));
        if (empty($separators)) {
            $separators = ['-'];
        }

        $slug = mb_strtolower($slug);
        $allowedSeparators = preg_quote(implode('', $separators), '/');
        $slug = preg_replace('/[\s' . ($allowedSeparators ? '|[^\w' . $allowedSeparators . ']' : '') . ']+/u', $separators[0], $slug);
        $allowed = 'a-z0-9' . $allowedSeparators;
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

        $trimPattern = '/^[' . $allowedSeparators . ']+|[' . $allowedSeparators . ']+$/';
        $slug = preg_replace($trimPattern, '', $slug);

        if ($maxLength > 0) {
            $slug = mb_substr($slug, 0, $maxLength);
            $slug = preg_replace('/[' . $allowedSeparators . ']+$/', '', $slug);
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

        // Заменяем запятую на точку
        $input = str_replace(',', '.', $input);

        if (is_numeric($input)) {
            if (strpos($input, '.') !== false || stripos($input, 'e') !== false) {
                return (float)$input;
            }
            return (int)$input;
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
        // Remove HTML and PHP tags
        $text = strip_tags($text);

        // Convert HTML entities to their corresponding characters
        $text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Remove emojis and smileys (Unicode ranges)
        $text = preg_replace('/[\x{1F600}-\x{1F64F}]/u', '', $text); // Smileys & emoticons
        $text = preg_replace('/[\x{1F300}-\x{1F5FF}]/u', '', $text); // Symbols & pictographs
        $text = preg_replace('/[\x{1F680}-\x{1F6FF}]/u', '', $text); // Transport & map symbols
        $text = preg_replace('/[\x{2600}-\x{26FF}]/u', '', $text);   // Miscellaneous symbols
        $text = preg_replace('/[\x{2700}-\x{27BF}]/u', '', $text);   // Dingbats

        // Remove all remaining special characters
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
     * @param bool $preClean Pre-cleaning and formatting
     * @return string Processed text
     */
    public static function truncate(
        string $text,
        int|array $characters = 15,
        string $after = "",
        string $before = "",
        bool $reverse = false,
        bool $preClean = false
    ): string {
        if ($preClean) {
            $text = static::text($text);
        }

        $length = mb_strlen($text);

        [$offset, $characters] = is_array($characters)
            ? [$characters[0] ?? 0, $characters[1] ?? 15]
            : [0, $characters];

        if ($length <= $characters) {
            return $text;
        }

        $truncated = match (true) {
            $reverse && $offset => mb_substr(mb_substr($text, 0, -$offset), -$characters),
            $reverse => mb_substr($text, -$characters),
            default => mb_substr($text, $offset, $characters)
        };

        return $before . trim($truncated) . $after;
    }

    /**
     * Clean content from critical threats
     * 
     * @param string $content Input content
     * @return string
     */
    public static function neutralize(string $content): string
    {
        $content = self::purgeNullBytes($content);
        $content = self::defuseUnicodeBombs($content);
        $content = self::breakLongLines($content);

        return $content;
    }

    /**
     * Remove null bytes and control characters
     * 
     * @param string $content Input content
     * @return string 
     */
    public static function purgeNullBytes(string $content): string
    {
        return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $content);
    }

    /**
     * Disable dangerous protocols in content
     * 
     * @param string $content Input content
     * @return string
     */
    public static function disarmProtocols(string $content): string
    {
        $replacements = [
            '/php:\/\/(filter|input|glob|expect|zip)/i' => 'php-safe://$1',
            '/phar:\/\//i' => 'phar-safe://',
            '/\b(file|ftp|gopher|jar|ldap|ssh2?):\/\//i' => '$1-safe://',
            '/data:(text\/(html|javascript|vbscript)|application\/(x-php|javascript))/i' => 'data-safe:$1',
            '/\b(javascript|vbscript|mocha):/i' => '$1-safe:',
            '/<!(?:ENTITY|DOCTYPE)\b[^>]*>/i' => '',
        ];

        return preg_replace(array_keys($replacements), array_values($replacements), $content);
    }

    /**
     * Break excessively long lines without line breaks
     * 
     * @param string $content Input content
     * @param int $detectLength Line length threshold for detection (default 10000)
     * @param int $cutLength Maximum allowed line length (default 1000)
     * @param string $suffix Suffix after truncation (default '')
     * @return string 
     */
    public static function breakLongLines(
        string $content,
        int $detectLength = 10000,
        int $cutLength = 1000,
        string $suffix = ''
    ): string {
        if ($detectLength <= 0 || $cutLength <= 0 || $cutLength >= $detectLength) {
            return $content;
        }

        $lines = explode("\n", $content);
        $result = [];

        foreach ($lines as $line) {
            $line = rtrim($line, "\r");

            if (mb_strlen($line) >= $detectLength) {
                $chunks = mb_str_split($line, $cutLength);
                $result[] = implode($suffix . "\n", $chunks) . $suffix;
            } else {
                $result[] = $line;
            }
        }

        return implode("\n", $result);
    }

    /**
     * Defuse unicode bombs by truncating excessive content
     * 
     * @param string $content Input content
     * @param bool $searchEverywhere Search everywhere
     * @return string 
     */
    public static function defuseUnicodeBombs(
        string $content,
        bool $searchEverywhere = false
    ): string {
        if ($searchEverywhere) {
            return str_replace("\xEF\xBB\xBF", '', $content);
        }

        return (substr($content, 0, 3) === "\xEF\xBB\xBF")
            ? substr($content, 3)
            : $content;
    }
}
