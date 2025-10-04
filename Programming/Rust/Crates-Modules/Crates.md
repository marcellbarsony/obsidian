# Crates

## Resources

- [Crates.io -  Crate registry](https://crates.io/)
- [Docs.rs - Crate documentation](https://docs.rs/)
- [Lib.rs](https://lib.rs/)

1. A package must have at least 1 crate
2. A package can have either 0 or 1 library crates
3. A package can have any number of binary crates

## Binary crates

If `main.rs` is defined in `src/`, a binary crate is created with the package's
name. `main.rs` will be the crate root and the root module.

## Dependencies

Dependencies added to `Cargo.toml` are available globally to all modules

```toml
# Cargo.toml
[dependencies]
module = "0.10.1"
```

### Mehod 1
```rs
// main.rs
pub fn random_number() {
  let random_number: u8 = rand::random();
  println!("{}", random_number);
}
```

### Mehod 2
```rs
// main.rs
use rand::random;

pub fn random_number() {
  let random_number: u8 = random();
  println!("{}", random_number);
}
```
