# String variables

String literal assigned to a variable
```c
char *s = "Hello, world!";

printf("%s\n", s);  // "Hello, world!"
```

## String variables as arrays

Declare strings as array
```c
char s[14] = "Hello, world!"; // Set size
char s[] = "Hello, world!";   // Set size automatically
```

Either array or pointer notation can be used to access characters or to loop
over them
```c
#include <stdio.h>

int main(void) {
    char *s = "Hello, world!";  // Pointer notation
    char s[] = "Hello, world!"; // Array notation

    for (int i = 0; i < 13; i++) {
        printf("%c\n", s[i]);
    }
}
```
