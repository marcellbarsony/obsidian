# Realloc

`Realloc()` takes a pointer to a previously-allocated memory
and the new size for the memory region to be.

```c
num_floats *= 2;

np = realloc(p, num_floats);  // ERROR: need bytes, not number of elements!

np = realloc(p, num_floats * sizeof(float));
```
