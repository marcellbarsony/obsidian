# Pointer to Array

In C, a pointer to an array is pointing to the first element of the array.

```c
#include <stdio.h>

int main(void) {
    int a[5] = {11, 22, 33, 44, 55};
    int *p;

    p = &a[0];  // p points to the array

    printf("%d\n", *p);  // "11"
}
```

Same with a shorthand
```c
p = &a[0];  // p points to the array
p = a;      // p points to the array (shorthand)
```
