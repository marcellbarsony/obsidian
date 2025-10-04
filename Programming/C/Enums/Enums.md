# Enums

C offers a way to have constant integer values by name

```c
enum {
  ONE=1,
  TWO=2
};

printf("%d %d", ONE, TWO);  // 1 2
```

Key differences between using `enum` and `define`
- `enum`s can only be integer types
- `#define` can define anything
- `enum`s are often shown by their symbolic identifier name in a debugger
- `#defined` numbers just show as raw numbers
  which are harder to know the meaning of while debugging

## Behavior of enum

`enum`s are automatically numbered (unless overridden)
```c
enum {
    SHEEP,  // Value is 0
    WHEAT,  // Value is 1
    WOOD,   // Value is 2
    BRICK,  // Value is 3
    ORE     // Value is 4
};

printf("%d %d\n", SHEEP, BRICK);  // 0 3
```
