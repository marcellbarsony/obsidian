# Integers

| Length  | Signed | Unsigned |
| ------- | ------ | -------- |
| 8-bit   | i8     | u8       |
| 16-bit  | i16    | u16      |
| 32-bit  | i32    | u32      |
| 64-bit  | i64    | u64      |
| 128-bit | i128   | u128     |
| arch    | isize  | usize    |

```rs
let a: i32 = 98_222; // Decimal
let b: i32 = 0xFF; // Hex
let c: i32 = 0o77; // Octal
let d: i32 = 0b1111_0000; // Binary
let e: u8 = b'A'; // Byte (u8 only)
```

### Arithmetic operations

```rs
// Addition
let sum: i32 = 5 + 10;

// Subtraction
let dif: f64 = 95.5 - 4.3;

// Multiplication
let mul: i32 = 4 * 30;

// Division
let div: f64 = 56.7 / 32.3;

// Remainder
let rem: i32 = 43 % 5;
```

### Conversion

```rs
let a: u8 = 12;
let b: u16 = 100;
let c = a as u16 + b;
```
