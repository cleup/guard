<?php

namespace Cleup\Guard\Purifier;

use Cleup\Guard\Purifier\Utils\Scrub;

class Sanitizer extends Ruleset
{
    protected bool $strict;

    /**
     * @param array $rules Validation and sanitization rules
     * @param bool $strict Whether to remove elements not defined in rules
     */
    public function __construct(array $rules, bool $strict = true)
    {
        parent::__construct($rules);
        $this->strict = $strict;
    }

    private function getTypedData(string $type, $value): mixed
    {
        $method = 'process' . ucfirst($type);

        if (method_exists($this, $method))
            return call_user_func_array([$this, $method], [$value]);

        return null;
    }

    /**
     * Sanitizes input data according to defined rules
     * 
     * @param array $data - Input data to sanitize
     * @return self 
     */
    public function sanitize(array $data): self
    {
        $this->data = [];

        foreach ($this->rules as $key => $rule) {
            $rule = $this->normalizeRule($rule);
            $hasDefault = isset($rule['default']);

            if (empty($rule['type']))
                $rule['type'] = 'string';

            if (!array_key_exists($key, $data)) {
                if ($hasDefault) {
                    $preparedDefault = $this->getTypedData($rule['type'], $rule['default']);

                    if (!is_null($preparedDefault))
                        $this->data[$key] = $preparedDefault;
                }
                continue;
            }

            $value = $data[$key];

            if (isset($rule['before']) && is_callable($rule['before'])) {
                $value = $rule['before']($value, $this);
            }

            try {
                $allow = true;

                if (isset($rule['values'])) {
                    $values = is_array($rule['values'])
                        ? $rule['values']
                        : [$rule['values']];

                    if (!in_array($value, $values)) {
                        $allow = false;

                        if (isset($rule['default'])) {
                            $preparedDefault = $this->getTypedData($rule['type'], $rule['default']);

                            if (!is_null($preparedDefault)) {
                                $value = $preparedDefault;
                                $allow = true;
                            }
                        }
                    }
                }

                if ($allow) {
                    $processedValue = $this->processValue($value, $rule);

                    if (isset($rule['after']) && is_callable($rule['after'])) {
                        $processedValue = $rule['after']($processedValue, $this);
                    }

                    $this->data[$key] = $processedValue;
                }
            } catch (\InvalidArgumentException $e) {
                if ($hasDefault) {
                    $preparedDefault = $this->getTypedData($rule['type'], $rule['default']);

                    if (!is_null($preparedDefault))
                        $this->data[$key] = $preparedDefault;
                }
            }
        }

        if ($this->strict) {
            $this->data = array_intersect_key($this->data, $this->rules);
        } else {
            $extraData = array_diff_key($data, $this->rules);

            foreach ($extraData as $extKey => $extItem) {
                if (!is_array($extItem)) {
                    $extraData[$extKey] = Scrub::escape(
                        Scrub::toString($extItem)
                    );
                } else {
                    unset($extraData[$extKey]);
                }
            }

            $this->data = array_merge($extraData, $this->data);
        }

        return $this;
    }

    /**
     * Processes value according to its type rules
     * 
     * @param mixed $value - Value to process
     * @param array $rule - Processing rules
     * @return mixed
     * @throws \InvalidArgumentException When value doesn't match required type
     */

    private function processValue(mixed $value, array $rule): mixed
    {
        $type = $rule['type'] ?? 'string';

        if (!$this->isValidType($value, $type)) {
            if ($type !== 'array') {
                throw new \InvalidArgumentException("Value does not match type $type");
            }
            return [];
        }

        if ($type !== 'array') {
            $method = 'process' . ucfirst($type);

            if (method_exists($this, $method)) {
                $value = call_user_func_array([$this, $method], [$value]);
                $scrubUtils = [
                    'escape',
                    'text',
                    'url',
                    'digits',
                    'email',
                    'slug',
                    'encode',
                    'stripWhitespace',
                    'translitCyrillic',
                    'normalizeString',
                    'truncate'
                ];

                foreach ($scrubUtils as $utilName) {
                    if (array_key_exists($utilName, $rule)) {
                        $verifyClass = __NAMESPACE__ . "\\Utils\\Scrub";
                        $arg = null;
                        $args = [$value];

                        if (!is_bool($rule[$utilName]) && !is_array($rule[$utilName])) {
                            $args[] = $rule[$utilName];
                        }

                        if (method_exists($verifyClass, $utilName)) {
                            $value = call_user_func_array(
                                [$verifyClass, $utilName],
                                $args
                            );
                        }
                    }
                }

                return $value;
            }

            return null;
        }

        return $this->processArray($value, $rule);
    }

    /**
     * Processes string value with optional filters
     * 
     * @param mixed $value - Value to process
     * @return string 
     */
    private function processString(mixed $value): string
    {
        return Scrub::toString($value);
    }

    /**
     * Processes array value with optional sub-rules or filters
     * 
     * @param mixed $value - Value to process
     * @param array $rule - Array processing rules
     * @return array
     */
    private function processArray(mixed $value, array $rule): array
    {
        $value = (array)$value;
        $isAssoc = $rule['assoc'] ?? !$this->isListArray($value);
        $result = [];

        if (empty($rule['data']))
            return [];

        if ($isAssoc) {
            $subSanitizer = new Sanitizer($rule['data'], $this->strict);
            $result = $subSanitizer->sanitize($value)->getAll();
        } else {
            foreach ($value as $listItem) {
                if (!$this->isListArray($listItem)) {
                    $subSanitizer = new Sanitizer($rule['data'], $this->strict);
                    $result[] = $subSanitizer->sanitize($listItem)->getAll();
                }
            }
        }

        return $result;
    }

    /**
     * Converts value to integer
     * 
     * @param mixed $value - Value to convert
     * @return int
     */
    private function processInteger(mixed $value): int
    {
        return intval($this->processNumeric($value));
    }

    /**
     * @see $this->processInteger()
     */
    private function processInt(mixed $value): int
    {
        return $this->processInteger($value);
    }

    /**
     * Converts value to float
     * 
     * @param mixed $value - Value to convert
     * @return float
     */
    private function processFloating(mixed $value): float
    {
        return floatval($this->processNumeric($value));
    }

    /**
     * @see $this->processFloating()
     */
    private function processFloat(mixed $value): int
    {
        return $this->processFloating($value);
    }

    /**
     * Converts value to numeric
     * 
     * @param mixed $value - Value to convert
     * @return int|float
     */
    private function processNumeric(mixed $value): int|float
    {
        return Scrub::toNumeric($value);
    }

    /**
     * @see $this->processNumeric()
     */
    private function processNumber(mixed $value): int
    {
        return $this->processNumeric($value);
    }

    /**
     * Converts value to boolean
     * 
     * @param mixed $value - Value to convert
     * @return bool
     */
    private function processBoolean(mixed $value): bool
    {
        $value = $this->processString($value);

        return boolval($value);
    }

    /**
     * @see $this->processBoolean()
     */
    private function processBool(mixed $value): int
    {
        return $this->processBoolean($value);
    }
}
