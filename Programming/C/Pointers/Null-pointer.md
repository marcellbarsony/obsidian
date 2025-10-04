# Null pointer

Any pointer variable of any pointer type can be set to `NULL`.
This indicates, that the pointer doesn't point to anything.

```c
int *p;
p = NULL;
```

Since `p` doesn't point to a value, dereferencing it is undefined behavior.

```c
int *p = NULL;
*p = 12;  // Undefined behavior
```

The pointer points to garbage unless explicitly assigned to point to an
address or `NULL`
