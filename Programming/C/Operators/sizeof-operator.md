# Sizeof operator

The `sizeof` operator tells the size (in bytes) that particular variable or data
type uses in memory.

```c
int a = 999;

printf("%zu\n", sizeof a);      // Prints 4
printf("%zu\n", sizeof(2 + 7)); // Prints 4
printf("%zu\n", sizeof 3.14);   // Prints 8
```

`sizeof` displays size in bytes of the type of the expression, not the size of the expression itself.

The return value of `sizeof` has the typ of `size_t`.
