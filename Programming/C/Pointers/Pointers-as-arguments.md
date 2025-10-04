# Pointers as arguments

Pointers (just like every single argument) are also getting copied into
function parameters and the function then uses the copy of the argument(s).

```c
#include <stdio.h>

void increment(int *p) {  // accepts a pointer to an int
    *p = *p + 1;        // add one to the thing p points to
}

int main(void) {
    int i = 10;
    int *j = &i;  // note the address-of; turns it into a pointer to i

    printf("i is %d\n", i);        // prints "10"
    printf("i is also %d\n", *j);  // prints "10"

    increment(j);                  // j is an int*--to i

    printf("i is %d\n", i);        // prints "11"!
}
```

The `increment()` function takes in `int *p` and makes it the copy of the
pointer `int *j`. Both the original pointer (`int *j`) and the copy (`int *p`)
point to the same address. Dereferencing either will modify the original
variable (`int i`).

This can be written more concisely

```c
printf("i is %d\n", i);  // prints "10"
increment(&i);
printf("i is %d\n", i);  // prints "11"!
```
