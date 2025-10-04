# Shadowing

Shadowing allows to overwrite a variable's type and value

```rs
fn main() {
    let shadowed = 1;

    {
        println!("Before being shadowed: {}", shadowed); // 1

        // This binding shadows the outer one
        let shadowed = "abc";

        println!("shadowed in inner block: {}", shadowed); // abc
    }

    // This binding *shadows* the previous binding
    let shadowed = 2;
    println!("shadowed in outer block: {}", shadowed); // 2
}
```
