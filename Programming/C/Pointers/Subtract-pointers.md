# Subtract pointers

Subtract two pointers to find the difference between them,
e.g. calculate how many `int`s there are between two `int*`s.


```c
#include <stdio.h>

int my_strlen(char *s) {
    // Start scanning from the beginning of the string
    char *p = s;

    // Scan until the NUL character
    while (*p != '\0')
        p++;

    // Return the difference in pointers
    return p - s;
}

int main(void) {
    printf("%d\n", my_strlen("Hello, world!"));  // 13
}
```

This only works if both pointers are pointing to the same array.
