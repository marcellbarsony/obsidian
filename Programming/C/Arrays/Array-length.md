# Array length

- [Beej's Guide to C programming - Getting the Length of an Array](https://beej.us/guide/bgc/html/split-wide/arrays.html#getting-the-length-of-an-array)

The length of the array has to be managed in a separate variable as C doesn't
record this information by default.

Take the `sizeof` the array, and then divide that by the size of each element to
get the length.

```c
int x[12];  // 12 ints

printf("%zu\n", sizeof x);     // 48 total bytes
printf("%zu\n", sizeof(int));  // 4 bytes per int

printf("%zu\n", sizeof x / sizeof(int));  // 48/4 = 12 ints
```

- The array consists of 12 integers
- The size of the array is 12 * 4 bytes = 48 bytes

The size of an array with a fixed number of elements can also be obtained
without declaring the array.

```c
sizeof(double [48]); // "384"
```

## Array of characters

The `sizeof` the array is the number of elements, since `sizeof(char)` is
1 byte.

### Scope

This trick only works in the scope in which the array was defined. If the array
is passed to a function, it doesn't work: when an array is "passed" to a
function, only a pointer to the first element is being passed, and that's what
`sizeof` measures.
