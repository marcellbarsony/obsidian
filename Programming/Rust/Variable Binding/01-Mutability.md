# Mutability

Variable bindings are immutable by default.
`mut` makes the binding mutable.

```rs
fn main() {
    let _immutable= 1;
    let mut mutable= 1;

    println!("Before mutation: {}", mutable);

    // Ok
    mutable += 1;

    println!("After mutation: {}", mutable);

    // Error! Cannot assign a new value to an immutable variable
    _immutable += 1;
}
```
