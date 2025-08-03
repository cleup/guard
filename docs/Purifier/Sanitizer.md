# Data Sanitizer Library

A flexible PHP data sanitization and validation library that provides clean, consistent data according to configurable rules.

## Features

- Type conversion: Automatic conversion to specified types (string, integer, float, boolean, array)
- Array handling: Supports both associative arrays and lists with recursive processing
- Custom rules: Define validation and sanitization logic for complex data structures
- Filter system: Built-in filters (trim, escape, etc.) with ability to add custom filters
- Recursive processing: Apply rules to nested data structures
- Default values: Fallback values for missing or invalid data
- Whitelist validation: Restrict values to predefined sets

## Basic Usage

A fast option that does not require special processing

```php
use Cleup\Guard\Purifier\Sanitizer;

$rules = [
    // This text string is still dangerous. To ensure safe data output, you need to use filters.
    'username' => 'string',
    /* Default filters:
        escape or esc - Escapes special html characters using the `htmlspecialchars` method.
        trim - Clears spaces at the start and end of a line.
        text - Completely clean and secure text, without tags, special characters and possible injections.
    */
    'userNameByFilter' => 'string:trim|escape'
    // Only the specified values are allowed (10, 77.3, 99).
    'allowedNumbers' => 'numeric;values:10,77.3,99'
    'age' => 'integer',
    'incorrectTypeValue' => 'integer;default:10'
    // Integers and floating point numbers (number|numeric)
    'nummericValue' => 'numeric',
    // (bool|boolean)
    'boolValue' => 'bool'
    // An unsafe parameter that ignores any data in the array. To set rules for an array, you can use the rule description method.
    'arrayData' => 'array',
];

$data = [
    'username' => '  <p>john_doe </p> ',  // '  <p>john_doe </p> ',
    'userNameByFilter' => '  <p>john_doe </p> ',  // '&lt;p&gt;john_doe &lt;/p&gt;';
    'incorrectTypeValue' => 'not integer', // default = 10
    'allowedNumbers' => 99,  // It will be equal to 99, as specified in the allowed values.
    'age' => 30,  // 30
    //'age' => '30' // 30 - It will be formatted as a number.
    //'age' => 'x12' // If no default value is provided, the data will be removed from the array.
    'nummericValue' => 3.14,
    'boolValue' => true, // true
    'arrayData' => ['hello' => 'world']  //  ['hello' => 'world']
    'unsafeArrat' => ['key' => 'value']  // It will be removed from the list, as it is not included in the rules.
];

$sanitizer = new Sanitizer($rules);
// Get all processed items.
$cleanData = $sanitizer->sanitize($data)->getAll();
```

A method for describing the rules in detail

```php
use Cleup\Guard\Purifier\Sanitizer;

$rules = [
   'name' => [
        'type' => 'string',
        'filters' => ['text'],
        'values' => ['Eduard', 'John', 'Alex'],
        'default' => 'Unknown'
    ],
    //
    'age' => [
        'type' => 'integer',
        // Custom processing of an element
        'before' => function($item, Sanitizer $sanitizer) {
            return intval($item) !== 0 ? $item : 1;
        },
        // A callback after the main element has been filtered.
        'after' => function($item, Sanitizer $sanitizer) {
            return $item > 99 ? 99 : $item;
        },
    ],

    'fields' => [
        'type' => 'array'
        'data' => [
            'city' => 'string:trim',
            'website' => 'string:text'
            // Or
            // 'city' => ['type' => 'string', 'filters' => ['trim']],
            // 'website' => ['type' => 'string', 'filters' => ['text']],
        ]
    ]
];

$data = [
    // It will be set to "Unknown" because it is not in the list, and the default value has already been specified. If the default value is not defined, the element will not be included in the data array.
   'name' => 'Jack',
   'age' => 121,
       'fields' => [
        'city' => ' London ',
        'website' => 'https://cleup.priveted.com'
    ]
];

// Process data
$sanitizer = new Sanitizer($rules);
$sanitizedObject = $sanitizer->sanitize($data);
$allData = $sanitizedObject->getAll();
// Get the processed element by key using the dot syntax.
$age = $sanitizedObject->get('age'); // 99
$arrayFiledCity = $sanitizedObject->get('age.city');  // 'London'
$arrayFiledWebsite = $sanitizedObject->get('age.city');  // 'https://cleup.priveted.com'
```

Advanced array processing capabilities.

```php
use Cleup\Guard\Purifier\Sanitizer;
// If the item is a list, the rules will apply to all the children elements of the list.
$rules = [
   'posts' => [
        'type' => 'array',
        'data' => [
            'title' => 'string:text'
            'content' => 'string:escape',
        ]
    ],
];


$data = [
    'posts' => [
        [
            'title' => 'My title',
            'content' => "<p>It's a great day to start something new.</p>"
        ],
        [
            'title' => 404, // The header will be deleted because it does not match the line type.
            'content' => 'Page not found'
        ]
    ]
];

$sanitizer = new Sanitizer($rules);
$cleanData = $sanitizer->sanitize($data)->getAll();
```

Unique and recursive rules regarding arrays and their component parts.

```php
use Cleup\Guard\Purifier\Sanitizer;

$rules = [
   'parentArray' => [
        'type' => 'array',
        // Recursively applies rules to all elements that are arrays, at infinite levels of nesting.
        'recursiveChildRules' => true,
        // Rules for child elements, which are arrays.
        'childRules' => [
            'title' => 'string',
            'views' => 'integer'
        ]
    ],
];

$data = [
    'parentArray' => [
        'title' => 'My tilte',
        'childArrayPosts' => [
            [
                'title' => 'My post title' // My post title,
                'fileds' => [
                    'views' => 100 // 100. The element will always be formatted as a number or deleted if it does not match this type.
                ]
            ]
        ]
    ]
];

$sanitizer = new Sanitizer($rules);
$cleanData = $sanitizer->sanitize($data)->getAll();
```
