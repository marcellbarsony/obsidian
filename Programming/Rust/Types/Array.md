# Arrays

- [Rust By Example - Arrays and Slices](https://doc.rust-lang.org/rust-by-example/primitives/array.html)
- [Rust - array](https://doc.rust-lang.org/std/primitive.array.html)

- **Sequence:** Fixed-size
- **Memory allocation:** Stack
- **Data types:** Same type
- **Indexing syntax:** `.` operator

## Declare

```rs
// List each element [x, y, z]
let byte: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

// Repeat expression [expr; N]
let byte [u8; 8] = [0; 8]; 
```

## Methods

```rs
let error_codes = [200, 404, 500];

// Access by index
let return_200 = error_codes[0];
let return_404 = error_codes[1];

// Access safely with .get
for i in 0..error_codes.len() + 1 { // Oops, one element too far!
    match error_codes.get(i) {
        Some(xval) => println!("{}: {}", i, xval),
        None => println!("Slow down! {} is too far!", i),
    }
}

// Length
let length = error_codes.len();

// Size on the stack
println!("Occupies {} bytes", mem::size_of_val(&error_codes))
```

## Slices

```rs
// Access by slice
let not_found = error_codes[0..1];

// Borrow as slice
slice(&error_codes);
slice(&error_codes[1 .. 2]);
```
