# String copy

Strings cannot be copied through the assignment (`=`) operator as it will only
copy the pointer to the first character.
```c
#include <stdio.h>

int main(void) {
    char s[] = "Hello, world!";
    char *t;

    t = s; // This makes a copy of the pointer!

    t[0] = 'z';

    printf("%s\n", s);  // "zello, world!"
}
```

## Strcopy

With `strcpy()` the destination pointer (`t`) is the first argument, and the
source pointer (`s`) is the second.
```c
#include <stdio.h>
#include <string.h>

int main(void) {
    char s[] = "Hello, world!";
    char t[100];  // 100 * 1 byte

    strcpy(t, s);

    t[0] = 'z';

    printf("%s\n", s);  // "Hello, world!"
    printf("%s\n", t);  // "zello, world!"
}
```
