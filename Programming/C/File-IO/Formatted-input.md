# Formatted input

## Security Note

`scanf()`-style functions can be hazardous with untrusted input.
If the field width is not specified, `%s` could overflow the buffer.
Worse, invalid numeric conversion result in undefined behavior.
The safe thing to do with untrusted input is to use `%s` with a field width,
then use functions like `strtol()` or `strtod()` to do the conversions.

## Formatted input

```whales.txt
blue 29.9 173
right 20.7 135
gray 14.9 41
humpback 16.0 30
```

These could be read with `fgets()` and then parse the string with `sscanf()`
and in that’s more resilient against corrupted files,
but in this case, let’s just use `fscanf()` and pull it in directly

The `fscanf()` function skips leading white space when reading,
and returns `EOF` on end-of-file or error.

```c
#include <stdio.h>

int main(void) {
    FILE *fp;
    char name[1024];  // Big enough for any line this program will encounter
    float length;
    int mass;

    fp = fopen("whales.txt", "r");

    while (fscanf(fp, "%s %f %d", name, &length, &mass) != EOF)
        printf("%s whale, %d tonnes, %.1f meters\n", name, mass, length);

    fclose(fp);
}
```

Output
```txt
blue whale, 173 tonnes, 29.9 meters
right whale, 135 tonnes, 20.7 meters
gray whale, 41 tonnes, 14.9 meters
humpback whale, 30 tonnes, 16.0 meters
```
