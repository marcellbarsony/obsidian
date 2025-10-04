# Building

## Sources

- [Beej's Guide to C - Compilation-details](https://beej.us/guide/bgc/html/split-wide/hello-world.html#compilation-details)

## clang

- [Beej's Guide to C - Building with clang](https://beej.us/guide/bgc/html/split-wide/hello-world.html#building-with-clang)

```sh
# Compile `source.c`
clang source.c

# Complie `source.c` to `out` (executable)
clang source.c -o out

# Complie `source.c` to `out` (executable) and add debug flag
clang -g source.c -o out
```
## gcc

- [Beej's Guide to C - Building with gcc](https://beej.us/guide/bgc/html/split-wide/hello-world.html#building-with-gcc)

```sh
# Compile `source.c` to `out` (executable)
gcc source.c -o out

# Compile multiple files
gcc source1.c source2.c source3.c -o out
```
