# Traits

- [Traits-defining-shared-behavior - The Rust Book](https://doc.rust-lang.org/book/ch10-02-traits.html)

A Trait (shared method) defines functionality a particular type has
and can share with other types.

## Define a Trait

Define the `Summary` Trait with default implementation
```rs
pub trait Summary {
    fn summarize(&self) -> String {
        String::from("Read more...");
    };
}
```

## Implement a Trait

Implement `Summary` Trait for `NewsArticle` Type
```rs
pub struct NewsArticle {
    pub headline: String,
    pub location: String,
    pub author: String,
    pub content: String,
}

impl Summary for NewsArticle {
    fn summarize(&self) -> String {
        format!("{}, by {} ({})", self.headline, self.author, self.location)
    }

    fn summarize_author(&self) -> String {
        format!("@{}", self.author)
    }
}
```

## Traits as parameters

Use Traits to define functions that accept many different types
```rs
pub fn notify(item: &impl Summary) {
    println!("Breaking news! {}", item.summarize());
}
```
