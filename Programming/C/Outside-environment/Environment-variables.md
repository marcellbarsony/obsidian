# Environment variables

Get environment variables

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *val = getenv("FROTZ");  // Get value

    // Check to make sure it exists
    if (val == NULL) {
        printf("Cannot find the FROTZ environment variable\n");
        return EXIT_FAILURE;
    }

    printf("Value: %s\n", val);
}
```

## Setting environment variables

```c
#include <stdio.h>

extern char **environ;  // MUST be extern AND named "environ"

int main(void) {
    for (char **p = environ; *p != NULL; p++) {
        printf("%s\n", *p);
    }

    // Or you could do this:
    for (int i = 0; environ[i] != NULL; i++) {
        printf("%s\n", environ[i]);
    }
}
```
