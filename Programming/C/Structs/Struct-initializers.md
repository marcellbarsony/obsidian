# Struct initializers

Initializing by putting values in the order they appear in the `struct`.
This won't work after the variable has been defined.
```c
struct car {
    char *name;
    float price;
    int speed;
};

struct car saturn = {"Saturn SL/2", 16000.99, 175};
```

Initializing without keeping the order of `struct`
```c
struct car saturn = {.speed=175, .name="Saturn SL/2"};
```

Missing field designators are initialized to zero.
