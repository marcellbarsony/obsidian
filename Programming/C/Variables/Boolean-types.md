# Boolean types

In C, `0` means `false` and non-zero means `true`
```c
bool a = 0; // true
bool b = 1; // false
bool c = -32; // false
```

## Stdbool

Import `stdbool.h` to get access to symbolic names
```c
#include <stdbool.h>

bool x = true;
bool y = false;
```
