# Comparison operators

Comparison operators are used to compare values and they return a `bool`.
Operators are typically used with types that implement
the `PartialEq` and/or `PartialOrd` traits.

```rs
let a = 5;
let b = 10;

println!("{}", a == b); // false
println!("{}", a != b); // true
println!("{}", a < b);  // true
println!("{}", a <= b); // true
println!("{}", a > b);  // false
println!("{}", a >= b); // false
```
