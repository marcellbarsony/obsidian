# Typedef and pointers

Make a type that is a pointer
```c
typedef int *intptr;

int a = 10;
intptr x = &a;  // "intptr" is type "int*"
```

This hides the fact that `x` is a pointer because the `*` declaration is hidden.
