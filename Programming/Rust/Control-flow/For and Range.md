# For and Range

Loop through values from `a` (inclusive) to `b` (exclusive)

```rs
for number in 1..10 {
    println!("Number: {}", number);
}
```

## For iterators

The `for in` consturct is able to interact with an `Iterator` in several ways

<!-- Iter {{{-->
### Iter

`iter` borrows each element of the collection through each iteration

```rs
fn main() {
    let names = vec!["Bob", "Frank", "Ferris"];

    for name in names.iter() {
        match name {
            &"Ferris" => println!("There is a rustacean among us!"),
            _ => println!("Hello {}", name),
        }
    }
    println!("names: {:?}", names);
}
```
<!--}}}-->

<!-- Into iter {{{-->
### Into iter

`into iter` consumes the collection so that on each iteration
the exact data is provided (moved within the loop)

```rs
fn main() {
    let names = vec!["Bob", "Frank", "Ferris"];

    for name in names.into_iter() {
        match name {
            "Ferris" => println!("There is a rustacean among us!"),
            _ => println!("Hello {}", name),
        }
    }
    println!("names: {:?}", names); // Error! Collection is moved
}
```
<!--}}}-->

<!-- Iter mut {{{-->
### Iter mut

`iter mut` mutably borrows each element of the collection,
allowing the collection to be modified in place

```rs
fn main() {
    let mut names = vec!["Bob", "Frank", "Ferris"];

    for name in names.iter_mut() {
        *name = match name {
            &mut "Ferris" => "There is a rustacean among us!",
            _ => "Hello",
        }
    }
    println!("names: {:?}", names);
}
```
<!--}}}-->
