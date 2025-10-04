# Macros

A macro is an identifier (placeholder) that gets expanded
to another piece of code before the compiler could see it.
```c
#include <stdio.h>

#define HELLO "Hello, world"
#define PI 3.14159

int main(void) {
    printf("%s, %f\n", HELLO, PI);
}
```

Macros could be defined without a value
```c
#define EXTRA_HAPPY
```


