# Repeated includes

An `#include` cycle is when `a.h` includes `b.h` and `b.h` includes `a.h`.
```sh
error: #include nested depth 200 exceeds maximum of 200
```

To avoid this, define a preprocessor variable at the first `#include`.
Then, for subsequent `#includes` check that the variable isn't defined.

For that variable name, take the name of the header file, make it uppercase,
and replace the dot with an underscore.

```c
#ifndef BAR_H   // If BAR_H isn't defined...
#define BAR_H   // Define it (with no particular value)

// File bar.h

int add(int, int);

#endif          // End of the #ifndef BAR_H
```
