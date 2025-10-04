# Copying and returning structs

Copy a `struct`
```c
struct car a, b;

b = a;
```

Returning a `struct` from a function also makes a similar copy to the receiving
variable.

This is not a "deep copy", all fields are copied as-is, including pointers.
