# Reading a line at a time

`fgets()` takes the following arguments:
- `s`: A pointer to a `char` buffer to hold bytes
- `sizeof s`: A maximum number of bytes to read
- `FILE*`: A file to read from


```c
#include <stdio.h>

int main(void) {
    FILE *fp;
    char s[1024];  // Big enough for any line this program will encounter
    int linecount = 0;

    fp = fopen("quote.txt", "r");

    while (fgets(s, sizeof s, fp) != NULL) 
        printf("%d: %s", ++linecount, s);

    fclose(fp);
}
```

- `fgets()` returns `NULL` on end-of-file or error.
- `fgets()` also NUL-terminate the string once done.
