# Passing by value

When an argument is passed to a function, a copy of that arguments gets made and
stored in the corresponding parameter.

If the argument is a variable, a copy of the value of that variable gets made
and stored in the parameter.

```c
#include <stdio.h>

void increment(int a) {
    a++;
}

int main(void) {
    int i = 10;
    increment(i);
    printf("i == %d\n", i); // 10
}
```

`printf` will print `10` since `increment` only modifies the copy (`a`) of `i`.
