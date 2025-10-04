# Modules

- [Medium - Rust modules and project structure](https://medium.com/codex/rust-modules-and-project-structure-832404a33e2e)

<!-- Scenario 1 {{{-->
## Scenario 1

Importing `config.rs` in `main.rs` (same directory)

```sh
# File System Tree
project_root
├─ cargo.toml
└─┬─ /src
  ├─ main.rs
  └─ config.rs

# Module System Tree
crate
└─ config
```

```rs
// main.rs
mod config;

fn main() {
    config::hello();
}
```

```rs
// config.rs
pub fn hello() {
    println!("Hello world");
}
```
<!--}}}-->

<!-- Scenario 2 {{{-->
## Scenario 2

Importing modules in `main.rs` (different directory)

```sh
# File System Tree
project_root
├─ cargo.toml
└─┬─ /src
  ├─ main.rs
  └─┬─ /module
    ├─ mod.rs
    └─ file.rs

# Module System Tree
crate
└─ module
     └─ file
```

```rs
// module/file.rs
pub fn hello() {
  println!("Hello world");
}
```

```rs
// module/mod.rs
// Version A
pub mod file;

// Version B
mod file;
pub use file::hello;    // Add `use` to map `hello()` to module
```

```rs
// main.rs - Version A/1
mod module;

fn main() {
    module::file::hello();
}

// main.rs - Version A/2
mod module;
use module::file;      // file is a module within `module`

fn main() {
    file::hello();
}

// main.rs - Version B
mod module;
use module::*;

fn main() {
    hello();
}
```
<!--}}}-->

<!-- Scenario 3 {{{-->
## Scenario 3

Importing modules from another module

```sh
# File System Tree
project_root
├─ cargo.toml
└─┬─ /src
  ├─ main.rs
  ├─┬─ /module1
  │ ├─ mod.rs
  │ └─ file1.rs
  └─┬─ /module2
    ├─ mod.rs
    └─ file2.rs

# Module System Tree
crate
├─ module1
│   └─ file1
└─ module2
    └─ file2
```
```rs
// main.rs
mod module1;
mod module2;

fn main() {
    module1::file1::hello();
}
```
```rs
// module1/mod.rs
pub mod file1;

// module1/file1.rs
fn hello() {
    crate::module2::file2::hello();
}
```
```rs
// module2/mod.rs
pub mod file2;

// module2/file2.rs
fn hello() {
    println!{"Hello world"};
}
```
<!--}}}-->
