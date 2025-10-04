# Input

Take input and append to the specified buffer

```rs
use std::io;

let mut var = String::new();

io::stdin():
    .read_line(&mut var)
    .expect("Failed to read line");
```
