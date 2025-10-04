# Remove directory

## remove_dir

Remove an empty directory

```rs
use std::fs;

fn main() -> std::io::Result<()> {
    fs::remove_dir("/path/to/dir")?;
    Ok(())
}
```

### Errors

This function will return an error if

- `path` doesn’t exist
- `path` isn’t a directory
- The user lacks permissions to remove the directory at the provided `path`
- The directory isn’t empty

### Example

```rs
use std::fs;

// Example 1
let result = match fs::remove_dir("/path/to/dir") {
    Ok(dir) => dir,
    Err(error) => panic!("[-] Cannot remove directory {:?}", error),
};

// Example 2
fs::remove_dir_all("/path/to/dir")
    .expect("[-] Cannot remove directory");
```

## remove_dir_all

Remove a non-empty directory

### Errors

See [fs::remove_file](https://doc.rust-lang.org/stable/std/fs/fn.remove_file.html)
and [fs::remove_dir](https://doc.rust-lang.org/stable/std/fs/fn.remove_dir.html)

### Example

```rs
use std::fs;

// Example
let result = match fs::remove_dir_all("/path/to/dir") {
    Ok(dir) => dir,
    Err(error) => panic!("[-] Cannot remove directory {:?}", error),
};

// Example 2
fs::remove_dir_all("/path/to/dir")
    .expect("[-] Cannot remove directory");
```
