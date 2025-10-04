# String length

The `strlen()` function returns a type `size_t`, which is an integer type.
```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char *s = "Hello, world!";

    printf("The string is %zu bytes long.\n", strlen(s)); // The string is 13 bytes long
}
```

## String termination

In C, a “string” is defined by two basic characteristics:
- A pointer to the first character in the string
- A zero-valued byte (NUL, `\0`) that indicates the end of the string

```c
int my_strlen(char *s) {
    int count = 0;

    while (s[count] != '\0')  // Single quotes for single char
        count++;

    return count;
}
```
