# Vectors

Vectors are re-sizable arrays.

[Vectors - Rust](https://doc.rust-lang.org/stable/std/vec/index.html)<br>
[Vectors - Rust By Example](https://doc.rust-lang.org/stable/rust-by-example/std/vec.html)

- **Sequence:** Growable
- **Memory allocation:** Heap

## Declaration

```rs
// Explicit
let v: Vec<i32> = Vec::new();

// vec! macro
let v: Vec<i32> = vec![];
let v = vec![1, 2, 3, 4, 5];
let v = vec![0; 10]; // ten zeroes
```

## Methods

```rs
let mut v = vec![1, 2, 3];

// Length
v.len();

// Push
v.push(4); // Output: [1, 2, 3, 4]

// Pop
let three = v.pop(); // Output: Some(4)

// Indexing
let three = &v[2]; // Output: 3
v[1] = v[1] + 5; // Output: [1, 7, 3]

match v.get(2) {
    Some(third) => println!("The third element is {}", third),
    None => println!("There's no third element"),
}
```
