# Conditional compilation

## If Defined (`#ifdef` and `#endif`)

Compile specific code depending on whether or not a macro is defined
```c
#include <stdio.h>

#define EXTRA_HAPPY

int main(void) {

#ifdef EXTRA_HAPPY
    printf("I'm extra happy!\n");
#endif

    printf("OK!\n");
}
```
