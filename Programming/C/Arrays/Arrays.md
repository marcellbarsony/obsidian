# Arrays

- [Beej's Guide to C programming - Arrays](https://beej.us/guide/bgc/html/split-wide/arrays.html#arrays)

An array in C is a collection of elements, all of the same data type, stored in
contiguous (back-to-back) memory locations.

- **Same Data Type**: All elements in an array must be of the same data type.
- **Contiguous Memory**: The elements of an array are stored in adjacent memory
  locations.
- **Fixed Size**: Arrays have a fixed size determined at the time of
  declaration. This size cannot be changed at runtime.
- **Zero-Based Indexing**: The first element is at index 0, the second at 1,
  and so on...

## Declare Arrays

Declare arrays without initialization
```c
#include <stdio.h>

int main(void) {
    int i;
    float f[4];

    f[0] = 3.14159;
    f[1] = 1.41421;
    f[2] = 1.61803;
    f[3] = 2.71828;

    for (i = 0; i < 4; i++) {
        printf("%f\n", f[i]);
    }
}
```

## Initialize Arrays

Initialize arrays with constants and set their size ahead of time
```c
#include <stdio.h>

int main(void) {
    int numbers[5] = {1, 2, 3, 4, 5}; // Set size
    int numbers[] = {1, 2, 3, 4, 5}; // Set size automatically

    int value = numbers[2]; // Access the 3rd element
}
```

Set specific array elements in the initializer
```c
int a[10] = {0, 11, 22, [5]=55, 66, 77};
// 0 11 22 0 0 55 66 77 0 0
```
