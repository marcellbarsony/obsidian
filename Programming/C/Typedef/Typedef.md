# Typedef

`typedef` is making a new alias for existing types.
```c
typedef int antelope;  // Make "antelope" an alias for "int"
antelope x = 10;       // Type "antelope" is the same as type "int"

typedef int antelope, bagel, mushroom;  // These are all "int"
```

`typedef` follows regular scoping rules,
it's common to find it at the global scope.
