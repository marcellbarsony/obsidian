# Scope

The scope of the variable is the block (`{}`) where it's defined.
```c
#include <stdio.h>

int main(void) {
    int a = 12;         // Local to outer block, but visible in inner block

    if  (a == 12) {
        int b = 99;     // Local to inner block, not visible in outer block

        printf("%d %d\n", a, b);  // OK: "12 99"
    }

    printf("%d\n", a);  // OK, still in a's scope

    printf("%d\n", b);  // ILLEGAL, out of b's scope
}
```
