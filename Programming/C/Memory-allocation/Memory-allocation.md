# Memory allocation

## Allocating (`malloc()`) and Deallocating (`free()`)

The `malloc()` function accepts a number of bytes to allocate,
and returns a void pointer to the allocated block of memory.

Since it's a `void*` any pointer type can be assigned to it.
```c
// Allocate space for a single int (sizeof(int) bytes-worth):
int *p = malloc(sizeof(int));

*p = 12;

printf("%d\n", *p);  // 12

free(p);

*p = 3490;  // ERROR: undefined behavior! Use after free()!
```

Use `memset()` to initialize the newly-allocated memory or see `calloc()`.
