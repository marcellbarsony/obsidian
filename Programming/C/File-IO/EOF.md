# EOF (End Of File)

`EOF` is an `int`, defined as a macro that `fgetc()` will return
when the end of the line has been reached
and reading another character is attempted.

```c
#include <stdio.h>

int main(void) {
    FILE *fp;
    int c;

    fp = fopen("hello.txt", "r");

    while ((c = fgetc(fp)) != EOF)
        printf("%c", c);

    fclose(fp);
}
```

- The result of `fgetc()` is assigned to `c`
- The result stored in `c` is compared against `EOF`
- This is operating a character at a time
