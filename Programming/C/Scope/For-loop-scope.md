# For loop scope

The variables declared inside the clause of a `for` loop can only be used
within the scope of the loop.
```c
for (int i = 0; i < 10; i++)
    printf("%d\n", i);

printf("%d\n", i);  // ILLEGAL--i is only in scope for the for-loop
```
