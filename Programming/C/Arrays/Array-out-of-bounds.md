# Array out of bounds

C does not prevent access to arrays out of bounds.

```c
#include <stdio.h>

int main(void) {
    int i;
    int a[5] = {22, 37, 3490, 18, 95};

    for (i = 0; i < 10; i++) {  // printing too many elements
        printf("%d\n", a[i]);
    }
}
```

This would result in undefined behavior
```sh
22
37
3490
18
95
32765
1847052032
1780534144
-56487472
21890
```
