# Command line arguments

- `argc` (argument count) is an integer storing the number of arguments,
  including the program name itself.

- `argv` (argument vector) is an array of strings (character pointers)
  where each string is a command-line argument.

```c
#include <stdio.h>

int main(int argc, char *argv[]) {
    for (int i = 0; i < argc; i++) {
        printf("arg %d: %s\n", i, argv[i]);
    }
}
```

```sh
./foo i like turtles
```

```sh
arg 0: ./foo
arg 1: i
arg 2: like
arg 3: turtles
```

The last `argv` is always `NULL`

```c
argv[argc] == NULL
```

## The alternate: `char **argv`

Since C doesn't differentiate between array notation and pointer notation
in the function signature, both signature are the same

```c
int main(int argc, char *argv[])
```
```c
int main(int argc, char **argv)
```

Walk along the `argv` array by bumping up the pointer until `NULL` hit.

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int total = 0;

    // Trick to get the compiler to stop warning
    // about the unused variable argc:
    (void)argc;

    for (char **p = argv + 1; *p != NULL; p++) {
        int value = atoi(*p);  // Use strtol() for better error handling

        total += value;
    }

    printf("%d\n", total);
}
```
