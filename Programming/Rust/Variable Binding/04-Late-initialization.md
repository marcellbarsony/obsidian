# Late initialization

It is possible to declare a variable binding first, then initialize later.

```rs
fn main() {
    let binding;

    {
        let x = 2;

        // Initialize the binding
        binding = x * x;
    }

    println!("a binding: {}", binding);

    let binding_2;

    // Error! Use of uninitialized binding
    println!("another binding: {}", binding_2);

    binding_2 = 1;

    println!("another binding: {}", binding_2);
}
```
