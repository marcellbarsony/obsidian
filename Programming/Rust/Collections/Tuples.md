# Tuple

- [Rust By Example - Tuples](https://doc.rust-lang.org/rust-by-example/primitives/tuples.html)
- [Rust - tuple](https://doc.rust-lang.org/std/primitive.tuple.html)

- **Sequence:** Fixed-size
- **Memory allocation:** Stack or Heap
- **Data types:** Any type (heterogenous)
- **Indexing syntax:** `.` operator


```rs
let tup = ("Lorem ipsum", 100_000);

// Tuple of tuple
let tup_of_tups = ((1u8, 2u16, 2u32), (4u64, -1i8), -2i16);

// Indexing (starts at 0)
let string = tup.0;
let number = tup.1;

// Destructuring
let (string, number) = tup;

// Reverse
println!("Reversed tuple {:?}", reverse(tup));
```
