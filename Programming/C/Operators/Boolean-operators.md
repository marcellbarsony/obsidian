# Boolean operators

Conditional expressions can be chained together with boolean operators.

| Operator | Boolean meaning |
| -------- | --------------- |
|    &&    |       and       |
|    ||    |       or        |
|    !     |       not       |

```c
// And
if (x < 10 && y > 20)
    printf("Doing something!\n");

// Not
if (!(x < 12))
    printf("x is not less than 12\n");
```
