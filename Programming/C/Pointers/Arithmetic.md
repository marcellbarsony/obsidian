# Arithmetic

```c
int a[5] = {11, 22, 33, 44, 55};

int *p = &a[0];  // Correct
int *p = a;      // Also correct

printf("%d\n", *p);        // 11
printf("%d\n", *(p + 0));  // 11
printf("%d\n", *(p + 1));  // 22
```

```c
int a[5] = {11, 22, 33, 44, 55};

int *p = &a[0];  // Or "int *p = a;"

for (int i = 0; i < 5; i++) {
    printf("%d\n", *(p + i));  // Same as p[i]!
}
```
