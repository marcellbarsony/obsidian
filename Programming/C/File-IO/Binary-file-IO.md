# Binary file I/O

Binary streams work similarly to text files, except the I/O subsytsem
doesn't perform any translations on the data but gives a raw stream of bytes.

Streams of bytes can contain `NUL` (end-of-string) characters,
thus `fread()` and `fwrite()` are used instead of `fprintf()`.

Write a sequence of byte values to disk, all at once:
```c
#include <stdio.h>

int main(void) {
    FILE *fp;
    unsigned char bytes[6] = {5, 37, 0, 88, 255, 12};

    fp = fopen("output.bin", "wb");

    // `fwrite` arguments:
    // - Pointer to data to write
    // - Size of each piece of data
    // - Count of each piece of data
    // - FILE*

    fwrite(bytes, sizeof(char), 6, fp);

    fclose(fp);
}
```

Read a byte at a time, then print them:
```c
#include <stdio.h>

int main(void) {
    FILE *fp;
    unsigned char c;

    fp = fopen("output.bin", "rb");

    // `fread` arguments:
    // - Pointer to data to write
    // - Size of each piece of data
    // - Count of each piece of data
    // - FILE*

    while (fread(&c, sizeof(char), 1, fp) > 0)
        printf("%d\n", c);

    fclose(fp);
}
```

`fread()` returns the number of bytes read, or `0` on `EOF`

Output
```sh
5
37
0
88
255
12
```
