# Strings

Strings are implemented as a collection of bytes.

- No null terminator (nullbyte)
- All strings valid UTF-8
- Immutable by default

## String types

### &str

Rust has only one string type (`str`) in the core language.<br>
A string slice is a reference to a portion of another string and it is usually
seen in its borrowed form (`&str`).

- Storage: Stack
- Ownership: Borrowed (read only)
- Growability: Cannot grow
- Mutability: Immutable
- Encoding: UTF-8

### String

Provided by standard library (rather than coded into the core language).<br>

- Storage: Heap
- Ownership: Owned
- Growability: Growable
- Mutability: Mutable
- Encoding: UTF-8

### &(u8; N)

A fixed-size slice of bytes.

- Storage: Stack or Heap
- Ownership: Borrowed
- Growability: Cannot grow
- Mutability: Immutable
- Encoding: Byte-level
- Cannot contain Unicode characters

### Vec<u8>

- Storage: Heap
- Ownership: Owned
- Growability: Growable
- Mutability: Mutable
- Encoding: Byte-level
- Cannot contain Unicode characters

### Cow<'a, str>

Data structure that can hold either a str slice or a String. This allows for efficient sharing of string data.

- Storage: Stack or Heap
- Ownership: Owned or borrowed
- Growability: Dependent on the underlying data
- Mutability: Dependent on the underlying data
- Encoding: UTF-8

### CStr

A raw string slice that represents a C-style string.

- Storage: Stack
- Ownership: Borrowed
- Growability: Cannot grow
- Mutability: Immutable
- Encoding: Byte-level

### OsStr

A raw string slice that represents a platform-specific string.<br>
It is similar to CStr but may have platform-specific limitations.

- Storage: Stack
- Ownership: Borrowed
- Growability: Cannot grow
- Mutability: Immutable
- Encoding: Byte-level

### OsString

It is similar to Vec<u8> but is specifically designed for platform-specific strings.
They are typically ised to represent file paths, environment variables, or other
OS-related strings.

- Storage: Heap
- Ownership: Owned
- Growability: Growable
- Mutability: Mutable
- Encoding: Byte-level

### Path

A representation of a file or directory path.<br>
It can be constructed from raw strings or other Path objects.

- Storage: Stack
- Ownership: Owned
- Growability: Cannot grow
- Mutability: Mutable
- Encoding: Platform-specific

### PathBuff

A mutable buffer for building or modifying Path objects.<br>
It provides efficient operations for adding, removing, and replacing segments of
a path.

- Storage: Heap
- Ownership: Owned
- Growability: Growable
- Mutability: Mutable
- Encoding: Platform-specific

## Sources

- [Strings - The Rust Book](https://doc.rust-lang.org/book/ch08-02-strings.html)
