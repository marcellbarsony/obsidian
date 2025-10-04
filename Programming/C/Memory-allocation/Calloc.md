# Calloc

`Calloc()` works similarly to `malloc()`, with two key differences:

- `Calloc()` takes the size and the number of elements
- `Calloc()` clears the memory to zero

```c
// Allocate space for 10 ints with calloc(), initialized to 0:
int *p = calloc(10, sizeof(int));

// Allocate space for 10 ints with malloc(), initialized to 0:
int *q = malloc(10 * sizeof(int));
memset(q, 0, 10 * sizeof(int));   // set to 0
```
