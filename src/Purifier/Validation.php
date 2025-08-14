<?php

namespace Cleup\Guard\Purifier;

class Validation extends Ruleset
{
    /**
     * @var array Validation errors
     */
    protected array $errors = [];

    /**
     * Validates input data according to defined rules
     * 
     * @param array $data Input data to validate
     * @return bool True if validation passes, false otherwise
     */
    public function validate(array $data): bool
    {
        $this->errors = [];
        $this->data = $data;

        foreach ($this->rules as $key => $rule) {
            $rule = $this->normalizeRule($rule);
            $isRequired = $rule['required'] ?? false;

            if (!array_key_exists($key, $data)) {
                if ($isRequired) {
                    $this->addError(
                        $key,
                        'Field is required',
                        'field_required'
                    );

                    continue;
                }
            }

            $value = $data[$key] ?? null;

            if (isset($rule['before']) && is_callable($rule['before'])) {
                $value = $rule['before']($value, $this);
            }

            $this->validateValue($key, $value, $rule);
        }

        return empty($this->errors);
    }

    /**
     * Validates a single value against its rules
     * 
     * @param string $key The field key being validated
     * @param mixed $value The value to validate
     * @param array $rule The validation rules to apply
     */
    protected function validateValue(string $key, mixed $value, array $rule): void
    {
        $type = $rule['type'] ?? 'string';

        if (isset($value)) {
            if ($type !== 'array' && !is_null($value)) {
                if (is_array($type)) {
                    $count = 0;

                    foreach ($type as $typeItem) {
                        if (!$this->isValidType($value, $typeItem)) {
                            $count++;
                        }
                    }

                    if ($count == count($type))
                        $this->addError(
                            $key,
                            "Value must be of type: " . implode(', ', $type),
                            "incorrect_type"
                        );
                } else {
                    if (!$this->isValidType($value, $type)) {
                        $this->addError(
                            $key,
                            "Value must be of type: $type",
                            "incorrect_type"
                        );
                    }
                }
            }

            if (isset($rule['values']) && isset($value)) {
                $allowedValues = is_array($rule['values']) ? $rule['values'] : [$rule['values']];

                if (!in_array($value, $allowedValues, true)) {
                    $this->addError(
                        $key,
                        "Value is not allowed",
                        "value_is_not_allowed"
                    );
                }
            }

            $minMaxTypes = [
                'number',
                'numeric',
                'string',
                'int',
                'integer',
                'float',
                'floating'
            ];

            $isNumber =   (
                $type == 'number' ||
                $type == 'numeric' ||
                $type == 'int' ||
                $type == 'integer' ||
                $type == 'float' ||
                $type == 'floating') &&
                (
                    is_int($value) ||
                    is_float($value) ||
                    is_numeric($value)
                );

            // Min
            if (
                isset($rule['min']) &&
                !is_array($rule['min']) &&
                in_array($type, $minMaxTypes)
            ) {
                $minError = false;

                if ($isNumber)
                    $minError = $value < $rule['min'];

                if ($type == 'string')
                    $minError = mb_strlen($value, 'UTF-8') < $rule['min'];

                if ($minError) {
                    $this->addError(
                        $key,
                        "The value is too small",
                        "small_value"
                    );
                }
            }

            // Max
            if (
                isset($rule['max']) &&
                !is_array($rule['max']) &&
                in_array($type, $minMaxTypes)
            ) {
                $maxError = false;

                if ($isNumber)
                    $maxError = $value > $rule['max'];

                if ($type == 'string')
                    $maxError = mb_strlen($value, 'UTF-8') > $rule['max'];

                if ($maxError) {
                    $this->addError(
                        $key,
                        "The value is too high.",
                        "high_value"
                    );
                }
            }

            $verifyUtils = [
                'email'            => 'The email address has an invalid format',
                'url'              => 'The URL has an invalid format',
                'allowedProtocol'  => 'The protocol is not allowed',
                'allowedHost'      => 'The host is not allowed',
                'domain'           => 'The domain has an invalid format',
                'ip'               => 'The IP address has an invalid format',
                'phone'            => 'The phone number has an invalid format',
                'dateFormat'       => 'The date has an invalid format',
                'notEmpty'         => 'The value is empty',
                'hexColor'         => 'The hex color is in the wrong format',
                'rgbaColor'        => 'The rgba color is in the wrong format',
                'rgbColor'         => 'The rgb color is in the wrong format',
                'hslColor'         => 'The hsl color is in the wrong format',
                'hslaColor'        => 'The hsla color is in the wrong format',
                'cssColor'         => 'The css color is in the wrong format',
                'latin'            => 'This meaning does not correspond to Latin',
                'positiveNumber'   => 'The value is not a positive number',
                'negativeNumber'   => 'The value is not a negative number',
                'even'             => 'The value is not an even number',
                'odd'              => 'This value is not an odd number',
                'leapYear'         => 'This year is not a leap year',
                'futureDate'       => 'The specified date does not exceed the current one',
                'pastDate'         => 'The specified date does not apply to the past',
                'today'            => 'This date is not the current one',
                'strongPassword'   => 'This password does not meet the security requirements',
                'palindrome'       => 'This value is not a palindrome',
                'romanNumeral'     => 'This value is not Roman numerals',
                'macAddress'       => 'The MAC address has an incorrect format',
                'json'             => 'The value does not match the JSON format',
                'containsEmoji'    => 'The value does not contain emojis',
                'bitcoinAddress'   => 'The Bitcoin address does not match the required format.',
                'maxLength'        => 'The value is too high.',
                'minLength'        => 'The value is too small'
            ];

            foreach ($verifyUtils as $utilName => $utilMessage) {
                if (array_key_exists($utilName, $rule)) {
                    $verifyClass = __NAMESPACE__ . "\\Utils\\Valid";
                    $arg = is_array($rule[$utilName])
                        ? $rule[$utilName]
                        : (!is_bool($rule[$utilName])
                            ? $rule[$utilName] : []
                        );

                    if (method_exists($verifyClass, $utilName)) {
                        if (
                            !call_user_func_array([
                                $verifyClass,
                                $utilName
                            ], [$value, $arg])
                        ) {
                            $this->addError(
                                $key,
                                $utilMessage,
                                "invalid_" . mb_strtolower(
                                    preg_replace(
                                        '/(?<=\w)(\p{Lu})/u',
                                        '_$1',
                                        $utilName
                                    ),
                                    'UTF-8'
                                )
                            );
                        }
                    }
                }
            }

            if (isset($rule['validate']) && is_callable($rule['validate'])) {
                $code = 'validation_failed';
                $result = $rule['validate']($value, $code, $this);
                if ($result !== true) {
                    $this->addError(
                        $key,
                        $result ?? 'Validation failed',
                        $code
                    );
                }
            }

            if ($type === 'array' && !is_null($value)) {
                if (!is_array($value)) {
                    $this->addError(
                        $key,
                        "Value must be of type: $type",
                        "incorrect_type"
                    );
                } else
                    $this->validateArray($key, $value, $rule);
            }
        }
    }

    /**
     * Validates array values against array-specific rules
     * 
     * @param string $key The field key being validated
     * @param array $value The array value to validate
     * @param array $rule The validation rules to apply
     */
    protected function validateArray(string $key, array $value, array $rule): void
    {
        $isAssoc = $rule['assoc'] ?? ($this->isAssociativeArray($value) || empty($value));

        if (isset($rule['data']) && is_array($rule['data'])) {
            $subValidator = new Validation($rule['data']);

            if (!$isAssoc && !isset($rule['assoc'])) {
                $this->validateListArray($key, $value, $subValidator);
            } else {
                if (!$subValidator->validate($value)) {
                    $this->mergeErrors($key, $subValidator->getErrors());
                }
            }
        }

        if (isset($rule['childRules']) && is_array($rule['childRules'])) {
            $isRecursive = $rule['recursiveChildRules'] ?? false;
            $childValidator = new Validation($rule['childRules']);

            foreach ($value as $itemKey => $item) {
                if (is_array($item)) {
                    if (!$childValidator->validate($item)) {
                        $this->mergeErrors("$key.$itemKey", $childValidator->getErrors());
                    }

                    if ($isRecursive) {
                        $this->applyChildRulesRecursively("$key.$itemKey", $item, $childValidator);
                    }
                }
            }
        }
    }

    /**
     * Validates a list (non-associative) array
     * 
     * @param string $key The field key being validated
     * @param array $list The list array to validate
     * @param Validation $validator The validator instance to use
     */
    protected function validateListArray(string $key, array $list, Validation $validator): void
    {
        $rules = $validator->getRules();
        $isAssocRules = $this->isAssociativeArray($rules);

        foreach ($list as $index => $item) {
            if (is_array($item)) {
                if ($isAssocRules) {
                    if (!$validator->validate($item)) {
                        $this->mergeErrors("$key.$index", $validator->getErrors());
                    }
                }
            } elseif (!$isAssocRules && !empty($rules)) {
                $firstRule = reset($rules);
                $this->validateValue("$key.$index", $item, $this->normalizeRule($firstRule));
            }
        }
    }

    /**
     * Applies child rules recursively to nested arrays
     * 
     * @param string $path The current path in the data structure
     * @param array $data The data to validate
     * @param Validation $validator The validator instance to use
     */
    protected function applyChildRulesRecursively(string $path, array $data, Validation $validator): void
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                if ($this->isAssociativeArray($value)) {
                    if (!$validator->validate($value)) {
                        $this->mergeErrors("$path.$key", $validator->getErrors());
                    }

                    $this->applyChildRulesRecursively("$path.$key", $value, $validator);
                } else {
                    $this->validateListArray("$path.$key", $value, $validator);
                }
            }
        }
    }

    /**
     * Adds a validation error to the errors collection
     * 
     * @param string $key The field key with the error
     * @param string $message The error message
     * @param string $code The error code
     */
    protected function addError(string $key, string $message, string $code): void
    {
        $this->errors[$key][] = [
            "message" => $message,
            "code" => $code,
        ];
    }

    /**
     * Merges nested validation errors with proper key prefixes
     * 
     * @param string $prefix The prefix to add to error keys
     * @param array $errors The errors to merge
     */
    protected function mergeErrors(string $prefix, array $errors): void
    {
        foreach ($errors as $key => $messages) {
            $fullKey = $prefix . (str_starts_with($key, '.') ? $key : ".$key");
            $this->errors[$fullKey] = $messages;
        }
    }

    /**
     * Gets all validation errors
     * 
     * @return array All validation errors
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * Gets the first error message for a specific field
     * 
     * @param string $key The field key to check
     * @return string|null The first error message or null if no errors exist
     */
    public function getFirstError(string $key): ?string
    {
        return $this->errors[$key][0] ?? null;
    }

    /**
     * Checks if a specific field has any validation errors
     * 
     * @param string $key The field key to check
     * @return bool True if errors exist, false otherwise
     */
    public function hasError(string $key): bool
    {
        return isset($this->errors[$key]);
    }
}
