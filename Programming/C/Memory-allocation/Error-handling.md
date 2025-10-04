# Error handling

The allocation functions return `NULL` if memory cannot be allocated
```c
int *x;

x = malloc(sizeof(int) * 10);

if (x == NULL) {
    printf("Error allocating 10 ints\n");
    // Handle the error here
}
```

The assignment and the condition can be done on the same line
```c
int *x;

if ((x = malloc(sizeof(int) * 10)) == NULL)
    printf("Error allocating 10 ints\n");
    // Handle the error here
}
```
