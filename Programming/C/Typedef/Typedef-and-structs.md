# `typedef` and `struct`s

`struct`s can be aliased with `typedef`.

```c
struct animal {
    char *name;
    int leg_count, speed;
};

//     original name   new name
//            v          v
//      |-----------| |----|
typedef struct animal animal;

struct animal y;  // This works
animal z;         // This also works because "animal" is an alias
```

## Example

```c
//     original name
//            v
//      |-----------|
typedef struct animal {
    char *name;
    int leg_count, speed;
} animal;         // New name

struct animal y;  // This works
animal z;         // This also works because "animal" is an alias
```

```c
//  Anonymous struct! It has no name!
//         v
//      |----|
typedef struct {
    char *name;
    int leg_count, speed;
} animal;                         // <-- new name

//struct animal y;  // ERROR: this no longer works--no such struct!
animal z;           // This works because "animal" is an alias
```

```c
typedef struct {
    int x, y;
} point;

point p = {.x=20, .y=40};

printf("%d, %d\n", p.x, p.y);  // 20, 40
```
