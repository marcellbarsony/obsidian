# Prototypes

Functions must be defined before they are being used. To notify the compiler in
advance, function prototypes can be declared to avoid implicit declaration.

```c
#include <stdio.h>

int foo(void);  // Prototype

int main(void) {
    int i;
    i = foo();
    printf("%d\n", i);  // 3490
}

int foo(void) {
    return 3490;
}
```
