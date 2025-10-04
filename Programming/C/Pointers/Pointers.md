# Pointers

```c
int n = 10;                                 // Declaration + Initialization
int *pointer = &n;                          // &: Address of n (8 bytes/64 bits)
printf("Address of n: %p\n", pointer);      // Show the address
printf("Value of n: %i\n", *pointer);       // Get the value (dereference)
printf("Address of abc[1]: %p\n", &abc[1]); // Get the address of abc[1]
```

## Pointer types

Pointers should be the same type they are pointing to
```c
int main(void) {
    int i;  // i's type is `int`
    int *p; // p's type is `pointer to an int`, or `int-pointer`
}
```

When there's an assignment into a pointer variable, the type of the right-hand
side of the assignment has to be the same type as the pointer variable
```c
int i;
int *p;  // uninitialized pointer (points to garbage)

p = &i;  // p is assigned the address of i--p now "points to" i
```
