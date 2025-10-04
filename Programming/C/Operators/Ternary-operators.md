# Ternary operators

Ternary operators are expressions whose value depends on the result of a
conditional embedded in it.
```c
// If x > 10, add 17 to y. Otherwise add 37 to y.
y += x > 10? 17: 37;

// Equivalent to
if (x > 10)
    y += 17;
else
    y += 37;
```
