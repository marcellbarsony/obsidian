# Multifile projects

Include `bar.h` from the current directory
```c
#include <stdio.h>
#include "bar.h"

int main(void) {
    printf("%d\n", add(2, 3));  // 5
}
```
