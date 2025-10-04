# Writing text files

Similarly to `fgetc()`, `fgets()`, and `fscanf()` to read text streams,
`fputc()`, `fputs()`, and `fprintf()` can write text streams.

Opening a file in `w` mode will instantly truncate the file to 0 bytes
for a full overwrite.
```c
#include <stdio.h>

int main(void) {
    FILE *fp;
    int x = 32;

    fp = fopen("output.txt", "w");

    fputc('B', fp);
    fputc('\n', fp);  // newline
    fprintf(fp, "x = %d\n", x);
    fputs("Hello, world!\n", fp);

    fclose(fp);
}
```

Output
```txt
B
x = 32
Hello, world!
```

Assign `stdout` to `fp` for console output
```c
fp = stdout;
```
