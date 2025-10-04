# String initializers

## String literal

Trying to mutate a string literal result in undefined behavior as it's memory
automatically managed by the compiler.
```c
char *s = "Hello, world!";

s[0] = 'z';  // Undefined behavior
```

## Array copy

Declaring the string as a mutable array copy allows mutating the string.
```c
char t[] = "Hello, again!";
t[0] = 'z';

printf("%s\n", t);  // "zello, again!"
```
