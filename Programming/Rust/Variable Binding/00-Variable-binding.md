# Variable binding

Rust provides type safety via static typing.

```rs
fn main() {
    let integer = 1u32;
    let boolean = true;
    let unit = ();

    // Copy `integer` into `copied_integer`
    let copied_integer = integer;

    println!("An integer: {:?}", copied_integer);
    println!("A boolean: {:?}", boolean);
    println!("Meet the unit value: {:?}", unit);

    // Unused variable
    let _unused_variable = 3u32;
}
```
