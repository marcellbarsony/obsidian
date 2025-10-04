# OpenOptions

[OpenOptions](https://doc.rust-lang.org/stable/std/fs/struct.OpenOptions.html)

```rs
use std:;fs::OpenOptions;
```

## Append

## Create

Sets the option to create a new file, or open it if it already exists.

In order for the file to be created, `OpenOptions::write` or
`OpenOptions::append` access must be used.

See also `std::fs::write()` for a simple function to create a file with a given
data.

```rs
let file = OpenOptions::new().write(true)
                             .create(true)
                             .open("foo.txt");
```

## Open

Open a file at path with the options specified by self.

```rs
let file = OpenOptions::new().read(true)
                             .open("foo.txt");
```

## Read

## Truncate

## Write
