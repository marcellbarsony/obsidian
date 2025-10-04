# Process

- [Rust std](https://doc.rust-lang.org/stable/std/process/index.html)<br>

## Print stdout

```rs
use std::process::Command;

let output = Command::new("ls")
    .arg("-al")
    .output()
    .expect("Failed command execution");

let stdout_string = String::from_utf8_lossy(&output.stdout).to_string();
println!("Output: {}", stdout_string);
```
