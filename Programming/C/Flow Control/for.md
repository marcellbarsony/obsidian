# For loop

In C, a for loop repeatedly executes a block of code a specific number of time,
based on an initializer, a condition, and an increment expression.
```c
for (initialization; condition; increment/decrement) {
    // code to be executed
}

// Example
int i = 0;

for (i = 0; i < 5; i++) {
    printf("i is %d\n", i);
}
```

## For vs. While

In C, both `for` and `while` loops allow code to be repeated, but they have
different typical use cases:

- **for** loop, if the number of iterations known ahead of time
- **while** loop, if the number of iterations isn't known ahead of time
```c
// Print numbers between 0 and 9 (inclusive)
int i = 0;

// While statement
while (i < 10) {
    printf("i is %d\n", i);
    i++;
}

// For loop
for (i = 0; i < 10; i++) {
    printf("i is %d\n", i);
}
```

## Empty for loop

```c
// Infinite loop
for(;;) {
    printf("Infinite loop until CTRL-C\n");
}
```
