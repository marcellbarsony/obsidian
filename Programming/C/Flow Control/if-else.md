# If-statements

`if-else` executes one block of code if a condition is true;
otherwise, it executes an alternative (`else`) block.
```c
int i = 10;

if (i == 10) {
    printf("i is 10");
} else {
    printf("i isn't 10");
}
```

`if-else-if` allows multiple conditions to be checked in sequence
```c
int i = 99;

if (i == 10)
    printf("i is 10");
else if (i == 20)
    printf("i is 20");
else if (i == 30)
    printf("i is 30");
else
    printf("i is something else");
```
