# Validation

A robust PHP data validation library that ensures data integrity and conformity to specified rules, with comprehensive error reporting.

## Features

- Supports string, integer, float, boolean, array types, as well as more than 30 additional data validations
- Required field validation: Mark fields as mandatory
- Value whitelisting: Restrict values to predefined sets
- Complex structure validation: Handle nested arrays and objects
- Custom validation: Define your own validation logic through callbacks
- Error collection: Detailed error reporting with field paths
- Conditional validation: Validate based on complex conditions
- Recursive validation: Apply rules to nested structures automatically

## Basic Usage

Simple validation with type checking and required fields:

```php
use Cleup\Guard\Purifier\Validation;

$rules = [
    'username' => 'required;type:string',
    'email' => 'required;type:email',
    'age' => 'type:integer',
    'score' => 'type:numeric',
    'active' => 'type:boolean',
    'role' => 'type:string;values:admin|user|guest'
    // using an array of rules
    'contact_info' => [                  // 'type:string|numeric;min:10;max:100'
        'type' => ['string', 'numeric'], // 'type:string|numeric'
        'min' => 10,                     // 'min:10'
        'max' => 100                     // 'max:100'
    ]
];

$data = [
    'username' => 'john_doe',
    'email' => 'john@example.com',
    'age' => 30,
    'score' => 85.5,
    'active' => true,
    'role' => 'user',
    'contact_info' => 'I live on earth'
];

$validator = new Validation($rules);
$isValid = $validator->validate($data);

if (!$isValid) {
    $errors = $validator->getErrors();
    // Handle errors
}
```

## Advanced Usage

Complex Array Validation

```php
use Cleup\Guard\Purifier\Validation;

$rules = [
    'posts' => [
        'type' => 'array',
        'required' => true,
        'data' => [
            'title' => 'required;type:string',
            'content' => 'required;type:string',
            'tags' => [
                'type' => 'array',
                'childRules' => [
                    'name' => 'required;type:string',
                    'count' => 'type:integer'
                ]
            ]
        ]
    ]
];

$data = [
    'posts' => [
        [
            'title' => 'First Post',
            'content' => 'Content here',
            'tags' => [
                ['name' => 'php', 'count' => 5],
                ['name' => 'validation', 'count' => 2]
            ]
        ]
    ]
];

$validator = new Validation($rules);
$isValid = $validator->validate($data);
```

#### Custom Validation Callbacks

```php
use Cleup\Guard\Purifier\Validation;

$rules = [
    'username' => [
        'type' => 'string',
        'required' => true,
        'validate' => function ($value, &$errorCode, $validator) {
            if (strlen($value) < 5) {
                $errorCode = 'username_too_short';
                return 'Username must be at least 5 characters long';
            }
            return true;
        }
    ],
    'password' => [
        'type' => 'string',
        'strongPassword' => true,  // Advanced strong password validation
        'required' => true,
        'validate' => function ($value, &$errorCode, $validator) {
            if (strlen($value) < 8) {
                $errorCode = 'password_too_weak';
                return 'Password must be at least 8 characters';
            }
            return true;
        }
    ]
];

$data = [
    'username' => 'john',
    'password' => '123'
];

$validator = new Validation($rules);
$isValid = $validator->validate($data);
$errors = $validator->getErrors();
```

#### Recursive Validation

The `childRules` parameter allows you to apply rules to child elements at the first level of the array. If `recursiveChildRules` is additionally used, then the rules apply to all child arrays with unlimited nesting levels, including lists of arrays.

```php
use Cleup\Guard\Purifier\Validation;

$rules = [
    'document' => [
        'type' => 'array',
        'recursiveChildRules' => true,
        'childRules' => [
            'title' => 'required;type:string',
            'author' => 'type:string'
        ]
    ]
];

$data = [
    'document' => [
        'title' => 'Main Document',
        'author' => 'John Doe',
        'chapters' => [
            [
                'title' => 'Chapter 1',
                'sections' => [
                    ['title' => 'Section 1.1'],
                    ['title' => 'Section 1.2']
                ]
            ],
            [
                'title' => 'Chapter 2'
            ]
        ]
    ]
];

$validator = new Validation($rules);
$isValid = $validator->validate($data);
```

## Error Handling

When validation fails, you can retrieve detailed error information:

```php
$errors = $validator->getErrors();

/*
Returns an array like:
[
    'field.path' => [
        [
            'code' => 'error_code',
            'message' => 'Error description'
        ],
        [
           ...
        ],
        ...
    ],
    'myArray.refArray.name' => [
        'code' => 'field_required',
        'message' => 'Field is required'
    ]
]
*/

$firstError = $validator->getFirstError('field.path');
/*
[
        'code' => 'error_code',
        'message' => 'Error description'
    ]
]
*/

$isError = $validator->hasError('field.path') // true
```

## Rule Syntax Reference

#### Basic Rules

- `type:<type>` - Validate field type (string, integer, numeric, boolean, array, email)
- `required:<true>` - Field must be present and not empty
- `values:value1|value2|value3` - Field must be one of the specified values
- `min:<number>` - The minimum value depends on the data type.
- `max:<number>` - The maximum value depends on the data type.
- And other validation options from the `Cleup\Guard\Purifier\Utils\Valid` utility: `email`, `url`, `allowedProtocol`, `allowedHost` `domain`, `ip`, `phone`, `dateFormat`, `notEmpty`, `hexColor`, `rgbaColor`, `rgbColor`, `hslColor`, `hslaColor`, `cssColor`, `latin`, `positiveNumber`, `negativeNumber`, `even`, `odd`, `leapYear`, `futureDate`, `pastDate`, `today`, `strongPassword`, `palindrome`, `romanNumeral`, `macAddress`, `json`, `containsEmoji`, `bitcoinAddress`, `maxLength`, `minLength`

#### Array Rules

- `data:<array>` - Define validation rules for array elements
- `recursiveChildRules` - Boolean to apply childRules recursively
- `childRules` - Rules to apply to all child elements

#### Custom Validation

- `before` - Callback to transform data before validation
- `validate` - Custom validation callback

#### Method Reference

- `validate(array $data)`: bool - Validate data against rules, returns true if valid
- `getErrors()`: array - Get validation errors after failed validation
- `getFirstError(string $key)`: array - Gets the first error message for a specific field
- `hasError(string $key)`: bool - Checks if a specific field has any validation errors
- `get()`: array - Get verified data after validation

This documentation covers the key aspects of the Validation class while maintaining a similar structure and style to the Sanitizer documentation.
