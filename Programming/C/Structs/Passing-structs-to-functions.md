# Passing structs to functions

In C, a `struct` can be passed to a function by
- Passing the `struct`
- Passing the pointer to the `struct`

There are two main scenarios where passing a pointer to a `struct` is beneficial
- The function needs to modify the original `struct`
- The `struct` is too large and copying it onto the stack is more expensive than
  copying a pointer

`saturn` is a `struct car`, so `&saturn` must be the address of the
`struct car`, AKA a pointer to a `struct car`, namely a `struct car*`.

And 799.99 is a float.
```c
#include <stdio.h>

struct car {
    char *name;
    float price;
    int speed;
};

void set_price(struct car *c, float new_price)

int main(void) {
    struct car saturn = {.speed=175, .name="Saturn SL/2"};

    set_price(&saturn, 799.99);

    printf("Price: %f\n", saturn.price);
}
```

Modifying the `price` variable doesn't work since `c` is a pointer.
```c
void set_price(struct car *c, float new_price) {
    c.price = new_price;  // ERROR!
}
```

Dereferencing the variable `c` to get to the `struct` itself.
```c
void set_price(struct car *c, float new_price) {
    (*c).price = new_price;  // Works, but is non-idiomatic
}
```

The arrow operator helps refer to fields in pointers to `structs`.
```c
void set_price(struct car *c, float new_price) {
    c->price = new_price;
}
```
