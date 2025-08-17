<?php

namespace Cleup\Guard\Purifier;

use Cleup\Helpers\Arr;

class Ruleset
{
    /**
     * @var array
     */
    protected array $data = [];

    /**
     * @var array
     */
    protected $types = [
        'string',
        'array',
        'int',
        'integer',
        'float',
        'floating',
        'number',
        'numeric',
        'bool',
        'boolean'
    ];

    /**
     * @var array
     */
    protected $rules = [];

    /**
     * @param array $rules Validation and sanitization rules
     */
    public function __construct(array $rules)
    {
        $this->setRules($rules);
    }

    /**
     * Sets new sanitization rules
     * 
     * @param array $rules New rules to apply
     * @return self
     */
    public function setRules(array $rules): self
    {
        $this->rules = $rules;

        return $this;
    }

    /**
     * Get the rules
     * 
     * @return array 
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    /**
     * Gets sanitized value by key
     * 
     * @param string $key - Data key
     * @param mixed $default - Default value
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return Arr::get($key, $this->data,  $default);
    }

    /**
     * Gets all data
     * 
     * @return array
     */
    public function getAll(): array
    {
        return $this->data;
    }

    /**
     * Parses string rule into structured array
     * 
     * @param string $rule - Rule string to parse
     * @return array
     */
    public function parseRule(string $rule)
    {
        $parsedRule = [];
        [$parts, $parsedRule] = $this->ruleParts(
            explode(';', $rule),
            $parsedRule
        );

        foreach ($parts as $part) {
            [$part, $parsedRule] = $this->rulePart($part, $parsedRule);

            if (!str_contains($part, ':')) {
                $singleProcess = $this->singleProcess($part);

                if (!is_null($singleProcess)) {
                    $parsedRule[$part] = $singleProcess;
                }
            } else {
                [$param, $value] = explode(':', $part, 2);
                $paramValues = str_contains($value, '|')
                    ? explode('|', $value)
                    : $value;

                [$param, $paramValues, $parsedRule] = $this->rulePartParams($param, $paramValues, $parsedRule);

                if (!is_array($paramValues)) {
                    $parsedRule[$param] = $this->process($paramValues, $parsedRule);
                } else {
                    $parsedRule[$param] = [];

                    foreach ($paramValues as $itemParam) {
                        $parsedRule[$param][] =  $this->process($itemParam, $parsedRule);
                    }
                }
            }
        }

        return $parsedRule;
    }

    /**
     * Converts string rules to array format
     * 
     * @param mixed $rule -  Rule to normalize
     * @return array
     */
    public function normalizeRule($rule): array
    {
        if (is_string($rule)) {
            return $this->parseRule($rule);
        }

        return $rule;
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
        return $value;
    }

    /**
     * Validates if value matches required type
     * 
     * @param mixed $value - Value to check
     * @param string $type - Required type
     * @return bool 
     */
    protected function isValidType(mixed $value, string $type): bool
    {
        switch ($type) {
            case 'string':
                return is_string($value);
            case 'array':
                return is_array($value);
            case 'int':
            case 'integer':
                return filter_var($value, FILTER_VALIDATE_INT) !== false;
            case 'float':
            case 'floating':
                return filter_var($value, FILTER_VALIDATE_FLOAT) !== false;
            case 'number':
            case 'numeric':
                return is_numeric($value);
            case 'bool':
            case 'boolean':
                return is_bool($value);
            default:
                return true;
        }
    }

    /**
     * Hook method for single item processing
     * 
     * @param string $part The part to process
     * @return bool
     */
    protected function singleProcess(string $part)
    {
        return true;
    }

    /**
     * Hook method for processing rule parts
     * 
     * @param array $parts The parts of the rule to process
     * @param array $parsedRule The parsed rule data
     * @return array Returns modified parts and parsed rule
     */
    protected function ruleParts(array $parts, array $parsedRule)
    {
        return [
            $parts,
            $parsedRule
        ];
    }

    /**
     * Hook method for processing a single rule part
     * 
     * @param mixed $part The rule part to process
     * @param array $parsedRule The parsed rule data
     * @return array Returns modified part and parsed rule
     */
    protected function rulePart(mixed $part, array $parsedRule)
    {
        return [
            $part,
            $parsedRule
        ];
    }

    /**
     * Hook method for processing rule parameters
     * 
     * @param string $param The parameter name
     * @param mixed $paramValues The parameter values
     * @param array $parsedRule The parsed rule data
     * @return array
     */
    protected function rulePartParams(string $param, mixed $paramValues, array $parsedRule)
    {
        return [
            $param,
            $paramValues,
            $parsedRule
        ];
    }

    /**
     * Checks if an array is a list (sequential numeric keys starting from 0)
     * 
     * @param array $array The array to check
     * @return bool
     */
    protected function isListArray(array $array): bool
    {
        return Arr::isList($array);
    }

    /**
     * Checks if an array is associative (has string keys or non-sequential numeric keys)
     * 
     * @param array $array The array to check
     * @return bool
     */
    protected function isAssociativeArray(array $array): bool
    {
        return Arr::isAssoc($array);
    }
}
