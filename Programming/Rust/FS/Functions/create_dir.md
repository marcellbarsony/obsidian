# Create directory

## create_dir

[create_dir](https://doc.rust-lang.org/stable/std/fs/fn.create_dir.html)

Create a new, empty directory

```rs
use std::fs;

fn main() -> std::io::Result<()> {
    fs::create_dir("/path/to/dir")?;
    Ok(())
}
```

### Errors

This function will return an error if

- The user lacks persmission
- The parent of the given path doesn't exists
- The path already exists


### Example

```rs
use std::fs;

// Example 1
match fs::create_dir("/path/to/dir") {
    Ok(dir) => dir,
    Err(error) => panic!("[-] Cannot create directory {:?}", error),
};

// Example 2
fs::create_dir("/path/to/dir");
    .expect("[-] Cannot create directory")
```

## create_dir_all

### Errors

This function will return an error in the following situations:

- If any directory in the path specified by path does not already exist and it
  could not be created otherwise

### Example

```rs
use std::fs;

// Example 1
match fs::create_dir("/path/to/dir") {
    Ok(dir) => dir,
    Err(error) => panic!("[-] Cannot create directory {:?}", error),
};

// Example 2
fs::create_dir("/path/to/dir");
    .expect("[-] Cannot create directory")
```
