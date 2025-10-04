# Character types

`char` type is an `int`, using only a single byte

```c
char c = 'B';

printf("%c\n", c);  // B
printf("%d\n", c);  // 66
```

`char` types are usually signed by default

```c
char a;           // Could be signed or unsigned
signed char b;    // Definitely signed
unsigned char c;  // Definitely unsigned
```

| `char` type     | Minimum | Maximum |
| --------------- | ------- | ------- |
| `signed char`   | -128    | 127     |
| `unsigned char` | 0       | 255     |
