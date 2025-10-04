# Multidimensional arrays

Arrays can be defined with any number of dimensions

```c
int a[10];
int b[2][7];
int c[4][5][6];
```

These are stored in memory in a [row-major order](https://en.wikipedia.org/wiki/Row-_and_column-major_order):
In a 2D array, the first index indicates the row and the second the column.

## Initializers on multidimensional arrays

Initializers can also be used on multidimensional arrays by nesting them

```c
#include <stdio.h>

int main(void) {
    int row, col;

    int a[2][5] = {      // Initialize a 2D array
        {0, 1, 2, 3, 4},
        {5, 6, 7, 8, 9}
    };

    for (row = 0; row < 2; row++) {
        for (col = 0; col < 5; col++) {
            printf("(%d,%d) = %d\n", row, col, a[row][col]);
        }
    }
}
```

<!-- Result {{{ -->
```sh
(0,0) = 0
(0,1) = 1
(0,2) = 2
(0,3) = 3
(0,4) = 4
(1,0) = 5
(1,1) = 6
(1,2) = 7
(1,3) = 8
(1,4) = 9
```
<!-- }}} -->

## Explicit indexes

Multidimensional arrays can also be initialized with explicit indexes

```c
// Make a 3x3 identity matrix
int a[3][3] = {[0][0]=1, [1][1]=1, [2][2]=1};
```

<!-- Result {{{ -->
```sh
1 0 0
0 1 0
0 0 1
```
<!-- }}} -->
