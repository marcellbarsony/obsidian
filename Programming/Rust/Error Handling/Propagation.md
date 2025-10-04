# Error handling - Propagation

```rs
use std::fs::File;
use std::io::{self, Read};

fn read_username_from_file() -> Result<String, io::Error> {
    // Open file
    let username_file_result = File::open("file.txt");
    let mut username_file = match username_file_result {
        Ok(file) => file,
        Err(e) => return Err(e),
    };

    // Read to string
    let mut username = String::new();
    match username_file.read_to_string(&mut username) {
        Ok(_) => Ok(username),
        Err(e) => Err(e),
    }
}
```

<!-- ? operator {{{-->
## ? operator

The `?` operator is used to unwrap `Result<T,E>` and `Option<T>` values

```rs
use std::fs::File;
use std::io::{self, Read};

fn read_username_from_file() -> Result<String, io::Error> {
    // Open file
    let mut username_file = File::open("file.txt")?;
    // Read to string
    let mut username = String::new();
    username_file.read_to_string(&mut username)?;
    Ok(username)
}
```
<!-- }}} -->

<!-- Method call chaining {{{-->
## Method call chaining

```rs
use std::fs::{self, File};
use std::io::{self, Read};

fn read_username_from_file() -> Result<String, io::Error> {
    let mut s = String::new();
    File::open("file.txt")?.read_to_string(&mut s)?;
    Ok(s)
}
```
<!-- }}} -->

<!-- read_to_string {{{-->
## Read to string

[read_to_string](https://doc.rust-lang.org/std/fs/fn.read_to_string.html)
reads the entire contents of a file into a string

```rs
use std::fs::{self, File};
use std::io::{self, Read};

fn read_username_from_file() -> Result<String, io::Error> {
    fs::read_to_string("file.txt");
}
```
<!-- }}} -->
