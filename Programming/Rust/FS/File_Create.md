# Filesystem

[std::fs](https://doc.rust-lang.org/stable/std/fs/index.html) - filesystem manipulation operations

```rs
use std::fs;
```

## Create & Write

Function [std::fs::write](https://doc.rust-lang.org/stable/std/fs/fn.write.html)

```rs
use std::fs::{File};
use std::io::{Write};

// Create
std::fs::File::create("/home/user/file.txt").unwrap();

// Create & Write
std::fs::write("foo.txt", "Lorem ipsum").unwrap();

let mut file = File::create("foo.txt").unwrap();
file.write_all(b"Hello, world!").unwrap();
```
