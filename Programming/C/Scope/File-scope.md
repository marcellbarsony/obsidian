# File scope

If a variable is defined outside a block, that variable has **file scope**.

```c
#include <stdio.h>

int shared = 10;    // File scope! Visible to the whole file

void func1(void) {
    shared += 100;  // Now shared holds 110
}

void func2(void) {
    printf("%d\n", shared);  // Prints "110"
}

int main(void) {
    func1();
    func2();
}
```

The variable has to be declared before the functions using it.
