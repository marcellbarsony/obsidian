# Pointer-Array equivalence

These array and pointer notations are equivalent and can be used interchangeably
```c
a[b] == *(a + b)
```

(in C11 §6.5.2.1¶2):
```
E1[E2] is identical to (*((E1)+(E2)))
```

```c
#include <stdio.h>

int main(void) {
    int a[] = {11, 22, 33, 44, 55};

    int *p = a;  // p points to the first element of a, 11

    // Print all elements of the array a variety of ways:

    for (int i = 0; i < 5; i++)
        printf("%d\n", a[i]);      // Array notation with a

    for (int i = 0; i < 5; i++)
        printf("%d\n", p[i]);      // Array notation with p

    for (int i = 0; i < 5; i++)
        printf("%d\n", *(a + i));  // Pointer notation with a

    for (int i = 0; i < 5; i++)
        printf("%d\n", *(p + i));  // Pointer notation with p

    for (int i = 0; i < 5; i++)
        printf("%d\n", *(p++));    // Moving pointer p
        //printf("%d\n", *(a++));    // Moving array variable a--ERROR!
}

```

In the case of an array variable, pointer or array notation both can be used
to access elements.
