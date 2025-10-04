# Pre-Increment & Post-Increment

```c
x++  // Increment
++x  // Pre-Increment
y--  // Decrement
--y  // Pre-Decrement
```

## Pre-Increment

The value is incremented first according to the precedence
and then the less priority operations are done.
```c
result = ++var;

// Expanded as
var = var + 1;
result = var;
```

## Post-Increment

The increment operation is performed after all the other operations are done.
```c
result = var++;

// Expanded as
result = var;
var = var + 1;
```
