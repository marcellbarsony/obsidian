# Scope

Variable bindings have a scope and live in a scope block

```rs
fn main() {
    let long_lived_binding = 1;

    // This block has a smaller scope than the main function
    {
        let short_lived_binding = 2;

        println!("Inner short: {}", short_lived_binding); // Ok
        println!("Outer long: {}", long_lived_binding); // Ok
    }

    println!("Outer short: {}", short_lived_binding); // Error
    println!("Outer long: {}", long_lived_binding); // Ok
}
```
