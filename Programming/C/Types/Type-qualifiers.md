# Type qualifiers

## Const

`const` values cannot be changed
```c
const int X = 2;

X = 4;  // can't assign to a constant
```

### `const` and pointers

The value the pointer points so cannot be changed
```c
int x[] = {10, 20};
const int *p = x; 

p++;  // p can be modified

*p = 30; // Can't change what it points to
```

<!--TODO-->
