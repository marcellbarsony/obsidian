# Structs

In C, `struct` is a user-definable, composite data type that groups together
variables under a single name, allowing different data types to be organized in
a single unit.

Structs are useful for organizing related data that belong to a logical entity.

## Declaring structs

Declare a struct type `struct car`
```c
struct car {
    char *name;
    float price;
    int speed;
};
```
Declare uninitialized variable `saturn` of type `struct saturn`
```c
struct car saturn;
```
Declare initialized variables and access them
```c
saturn.name = "Saturn SL/2";
saturn.price = 15999.99;
saturn.speed = 175;

printf("Name:           %s\n", saturn.name);
printf("Price (USD):    %f\n", saturn.price);
printf("Top Speed (km): %d\n", saturn.speed);
```
