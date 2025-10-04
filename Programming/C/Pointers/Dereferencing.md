# Dereferencing

A pointer variable can be thought of as referring to another variable by
pointing to it.

```c

#include <stdio.h>

int main(void) {
    int i;
    int *p;  // pointer is a type `int*`

    p = &i;  // p now points to i / holds the address of i

    i = 10;  // i is now 10
    *p = 20; // the thing p points to (namely i!) is now 20!!

    printf("i is %d\n", i);   // prints "20"
    printf("i is %d\n", *p);  // "20"! dereference-p is the same as i!
}
```
