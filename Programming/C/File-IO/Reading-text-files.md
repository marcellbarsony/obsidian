# Reading text files

Text files are logically a sequence of lines separated by newlines (`\n`).
```c
#include <stdio.h>

int main(void) {
    FILE *fp;                      // Variable to represent open file

    fp = fopen("hello.txt", "r");  // Open file for reading

    int c = fgetc(fp);             // Read a single character
    printf("%c\n", c);             // Print char to stdout

    fclose(fp);                    // Close the file when done
}
```

- `fopen()` returned a `FILE*` that could be used later
- `fopen()` will return `NULL` in the case of error
- `"r"` stands for open text stream for reading
- `fgetc()` gets a character from the stream
- `fclose()` is closing the stream
