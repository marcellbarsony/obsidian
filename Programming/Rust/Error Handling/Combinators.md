# Option combinator methods

- [Rust Std :: Option Combinators](https://doc.rust-lang.org/std/option/enum.Option.html)

### [map](https://doc.rust-lang.org/stable/std/option/enum.Option.html#method.map)

Map a function on to the value inside of an `Option<T>`, unless `None`
```rs
// Returns the extension of the given file name, where the extension is defined
// as all characters succeeding the first `.`.
// If `file_name` has no `.`, then `None` is returned.
fn extension(file_name: &str) -> Option<&str> {
    find(file_name, '.').map(|i| &file_name[i+1..])
}
```

### [unwrap_or](https://doc.rust-lang.org/stable/std/option/enum.Option.html#method.unwrap_or)

Assign a default value when an `Option` is `None`
```rs
fn unwrap_or<T>(option: Option<T>, default: T) -> T {
    match option {
        None => default,
        Some(value) => value,
    }
}
```

### [and_then](https://doc.rust-lang.org/stable/std/option/enum.Option.html#method.and_then)

Chain failable computations
```rs
fn file_path_ext_explicit(file_path: &str) -> Option<&str> {
    match file_name(file_path) {
        None => None,
        Some(name) => match extension(name) {
            None => None,
            Some(ext) => Some(ext),
        }
    }
}

// Replace double matching with `and_then` combinator
fn file_path_ext(file_path: &str) -> Option<&str> {
    file_name(file_path).and_then(extension)
}
```
