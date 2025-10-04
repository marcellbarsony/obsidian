# Copy

[Rust std](https://doc.rust-lang.org/stable/std/fs/fn.copy.html)<br>

```rs
use std::fs;
use std::path::Path;

let src = Path::new("/path/to/src");
let dst = Path::new("/path/to/dst");
fs::copy(src, dst)
    .expect("Failed to copy file");
```
