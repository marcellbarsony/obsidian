# Conditional operators

```c
a == b; // True if a = b
a != b; // True if a != b
a < b;  // True if a < b
a > b;  // True if a > b
a <= b; // True if a <= b
a >= b; // True if a >= b
```

## Boolean operators

| Operator | Boolean meaning |
| -------- | --------------- |
|    &&    |      and        |
|    ||    |      or         |
|    !     |      not        |

## Sizeof operator

The `sizeof` operator tells the size (in bytes) of a variable or data type uses
in memory.
```c
int x = 999;

printf("%zu\n", sizeof x);
printf("%zu\n", sizeof(2 + 7));
printf("%zu\n", sizeof 3.14);
```
