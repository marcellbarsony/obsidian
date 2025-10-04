# Error handling

[Error Handling - The Rust Book](https://doc.rust-lang.org/book/ch09-00-error-handling.html)<br>

<!-- Backtrace {{{-->
## Backtrace

Display backtrace in error message

```sh
# note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
$ RUST_BACKTRACE=1 cargo run
```
<!-- }}} -->

<!-- Unrecoverable errors {{{-->
## Unrecoverable errors

Unrecoverable errors with `panic!` macro

```rs
panic!("Panic!");
```
<!-- }}} -->

<!-- Recoverable errors {{{-->
## Recoverable errors

Recoverable errors with [Result<T, E>](https://doc.rust-lang.org/std/result/)

```rs
enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

### Match errors

[match](https://doc.rust-lang.org/std/keyword.match.html) expression

```rs
let file = match file_result {
    Ok(file) => file,
    Err(error) => panic!("Problem with file: {:?}", error),
};
```

Match [ErrorKind](https://doc.rust-lang.org/std/io/enum.ErrorKind.html)s

```rs
use std::io::ErrorKind;

let file = match file_result {
    Ok(file) => file,
    Err(error) => match error.kind() {
        ErrorKind::NotFound => match File::create("file.txt") {
            Ok(fc) => fc,
            Err(e) => panic!("File not found: {:?}", e),
        },
        other_error => {
            panic!("Problem opening the file: {:?}", other_error);
        }
    },
};
```
<!-- }}} -->
