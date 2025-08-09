<?php

namespace Cleup\Guard\Purifier;

use Cleup\Guard\Purifier\Utils\Scrub;

class Sanitizer extends Ruleset
{
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

            if (!array_key_exists($key, $data)) {
                if ($hasDefault)
                    $this->data[$key] = $rule['default'];

                continue;
            }

            $value = $data[$key];

            if (
                isset($rule['before']) &&
                is_callable($rule['before'])
            ) {
                $value = $rule['before']($value, $this);
            }

            try {
                $allow = true;

                if (isset($rule['values'])) {
                    $values = is_array($rule['values'])
                        ? $rule['values']
                        : [$rule['values']];

                    if (!in_array($value,  $values, true)) {
                        $allow = false;

                        if (isset($rule['default'])) {
                            $value = $rule['default'];
                            $allow = true;
                        }
                    }
                }

                if ($allow) {
                    $processedValue = $this->processValue($value, $rule);

                    if (
                        isset($rule['after']) &&
                        is_callable($rule['after'])
                    ) {
                        $processedValue = $rule['after']($processedValue, $this);
                    }

                    $this->data[$key] = $processedValue;
                }
            } catch (\InvalidArgumentException $e) {
                if ($hasDefault)
                    $this->data[$key] = $rule['default'];
            }
        }

        return $this;
    }

    /**
     * Processes value according to its type rules
     * 
     * @param mixed $value - Value to process
     * @param array $rule - Processing rules
     * @return mixed
     */
    protected function process($value, $rule)
    {
        return $this->processValue($value, $rule);
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
            if ($type !== 'array')
                throw new \InvalidArgumentException("Value does not match type $type");
            else
                return [];
        }

        switch ($type) {
            case 'string':
                return $this->processString($value, $rule);
            case 'array':
                return $this->processArray($value, $rule);
            case 'int':
            case 'integer':
                return $this->processInteger($value);
            case 'float':
            case 'floating':
                return $this->processFloating($value);
            case 'number':
            case 'numeric':
                return $this->processNumeric($value);
            case 'bool':
            case 'boolean':
                return $this->processBoolean($value);
            default:
                return $value;
        }
    }

    /**
     * Processes string value with optional filters
     * 
     * @param mixed $value - Value to process
     * @param array $rule - String processing rules
     * @return string 
     */
    private function processString(mixed $value, array $rule): string
    {
        $value = strval($value);

        if (isset($rule['filters'])) {
            foreach ($rule['filters'] as $filter) {
                $value = $this->applyStringFilter($value, $filter);
            }
        }

        return $value;
    }

    /**
     * Applies specific filter to string value
     * 
     * @param string $value - String to filter
     * @param string $filter - Filter to apply
     * @return string
     */
    private function applyStringFilter(string $value, string $filter): string
    {
        switch ($filter) {
            case 'esc':
            case 'escape':
                return Scrub::escape($value);
            case 'trim':
                return trim($value);
            case 'lower':
                return mb_strtolower($value, 'UTF-8');
            case 'upper':
                return mb_strtoupper($value, 'UTF-8');
            case 'text':
                return Scrub::filterText($value);
            default:
                return $value;
        }
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

        if (isset($rule['childRules']) && is_array($rule['childRules'])) {
            $isRecursiveChildRules = !empty($rule['recursiveChildRules']);
            $childSanitizer = new Sanitizer($rule['childRules']);

            foreach ($value as $key => &$item) {
                if (is_array($item)) {
                    if ($isRecursiveChildRules) {
                        $item = $this->applyChildRulesRecursively($item, $childSanitizer);
                    } elseif (
                        !isset($rule['data'][$key]) ||
                        (is_string($rule['data'][$key]) && $rule['data'][$key] === 'array')
                    ) {
                        $item = $childSanitizer->sanitize($item);
                    }
                }
            }

            unset($item);
        }

        if (isset($rule['data']) && is_array($rule['data'])) {
            $subSanitizer = new Sanitizer($rule['data']);

            if (!$isAssoc && !isset($rule['assoc'])) {
                $processed = $this->processListArray($value, $subSanitizer);
            } else {
                $processed = $subSanitizer->sanitize($value);
            }

            return empty($processed->getAll())
                ? []
                : $processed->getAll();
        }

        if (isset($rule['filters']) && is_array($rule['filters'])) {
            foreach ($value as &$item) {
                if (is_string($item)) {
                    foreach ($rule['filters'] as $filter) {
                        $item = $this->applyStringFilter($item, $filter);
                    }
                }
            }
            unset($item);
        }

        return empty($value) ? [] : $value;
    }

    /**
     * Processes array as a list (non-associative array)
     * 
     * @param array $list - List array to process
     * @param Sanitizer $sanitizer - Sanitizer with rules to apply
     * @return array Processed list with invalid items removed
     */
    private function processListArray(array $list, Sanitizer $sanitizer): array
    {
        $result = [];
        $rules = $sanitizer->getRules();
        $isAssocRules = $this->isAssociativeArray($rules);

        foreach ($list as $item) {
            try {
                if (is_array($item)) {
                    $processed = $isAssocRules ? $sanitizer->sanitize($item) : $item;

                    if (!empty($processed)) {
                        $result[] = $processed;
                    }
                } else {
                    if (!$isAssocRules && !empty($rules)) {
                        $firstRule = reset($rules);
                        $processed = $this->processValue($item, $this->normalizeRule($firstRule));
                        $result[] = $processed;
                    } else {
                        $result[] = $item;
                    }
                }
            } catch (\InvalidArgumentException $e) {
                continue;
            }
        }

        return empty($result) ? [] : $result;
    }

    private function applyChildRulesRecursively(array $data, Sanitizer $childSanitizer): array
    {
        $result = [];

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                if ($this->isListArray($value)) {
                    foreach ($value as $keyList => $listValue) {
                        if (!isset($result[$key]))
                            $result[$key] = [];

                        $processed = $this->applyChildRulesRecursively($listValue, $childSanitizer);

                        if (!empty($processed)) {
                            $sanitized =  $childSanitizer->sanitize($processed);
                            if (!empty($sanitized) && is_array($sanitized))
                                $result[$key][$keyList] = $sanitized;
                        }
                    }
                } else {
                    $processed = $this->applyChildRulesRecursively($value, $childSanitizer);

                    if (!empty($processed)) {
                        $result[$key] = $childSanitizer->sanitize($processed);
                    }
                }
            } else {
                try {

                    $processed = $childSanitizer->sanitize([$key => $value])[$key] ?? null;
                    $result[$key] = $processed;
                } catch (\InvalidArgumentException $e) {
                }
            }

            if (empty($result[$key]))
                unset($result[$key]);
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
        return intval($value);
    }

    /**
     * Converts value to float
     * 
     * @param mixed $value - Value to convert
     * @return float
     */
    private function processFloating(mixed $value): float
    {
        return floatval($value);
    }

    /**
     * Converts value to numeric
     * 
     * @param mixed $value - Value to convert
     * @return int|float
     */
    private function processNumeric(mixed $value): int|float
    {
        return Scrub::filterNumeric($value);
    }

    /**
     * Converts value to boolean
     * 
     * @param mixed $value - Value to convert
     * @return bool
     */
    private function processBoolean(mixed $value): bool
    {
        return boolval($value);
    }

    /**
     * @see Ruleset::ruleParts()
     * 
     * @param string $rule - Rule string to parse
     * @return array
     */
    protected function ruleParts($parts, $parsedRule)
    {
        $typeSegment = array_shift($parts);
        $typeParts = explode(':', $typeSegment, 2);
        $parsedRule = ['type' => $typeParts[0]];

        if (isset($typeParts[1])) {
            $parsedRule['filters'] = explode('|', $typeParts[1]);
        }

        return [$parts, $parsedRule];
    }

    /**
     * @see Ruleset::rulePartParams()
     * 
     * @param string $param The parameter name
     * @param mixed $paramValues The parameter values
     * @param array $parsedRule The parsed rule data
     * @return array
     */
    protected function rulePartParams($param, $paramValues, $parsedRule)
    {
        $paramValues =  (
            $parsedRule['type'] !== 'array' &&
            is_array($paramValues) &&
            $param === 'default'
        )
            ? $paramValues[0]
            : $paramValues;

        return [
            $param,
            $paramValues,
            $parsedRule
        ];
    }

    /**
     * @see Ruleset::singleProcess()
     * 
     * @param string $part The part to process
     * @return bool
     */
    protected function singleProcess($part)
    {
        return null;
    }
}
