# Open a file

[Rust By Example](https://doc.rust-lang.org/stable/rust-by-example/std_misc/file/open.html)<br>

```sh
use std::fs::File;

fn main() {
    let f = File::open("file.txt").unwrap();
}
```
