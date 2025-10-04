# Constants

Constants are values that cannot be changed after they are declared.
Constants cannot be set as a return value of a function
or any value calculated at runtime.

## Usage

Constants are typically used in places where the value is known at compile-time,
such as:
- Initializing variables
- Defining struct fields
- Passing values to functions
- Using them in expressions

## Declaring constants

```rs
const IDENTIFIER: TYPE = EXPRESSION;

// Examples
const PI: f64 = 3.14159;
const INTERGALACTICAL_SPEED: u32 = 120_000;
const FOOD_TYPES: [&str; 3] = ["pizza", "pasta", "burger"];
```
