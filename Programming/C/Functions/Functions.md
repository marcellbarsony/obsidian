# Functions

Functions can accept a variety of predeclared arguments and a return value.
A function parameter is a local variable into which the arguments are copied.

<!-- Example {{{ -->
```c
#include <stdio.h>

int plus_one(int n) {
    return n + 1;
}
```
<!-- }}} -->

## Main

`main()` is the function executed when the program is started.

### Command line parameters

- `argc`: The number of command line parameters
- `argv`: Parameters as an array of strings

```c
int main(int argc, char *argv[])
```

### No command line parameters

```c
int main(void)
```

## Void

The following function doesn't take any arguments and returns no value.
```c
#include <stdio.h>

void hello(void) {
    printf("Hello, world!\n");
}

int main(void) {
    hello();
}
```
