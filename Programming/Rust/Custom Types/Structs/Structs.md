# Structs

[Structs - Rust By Example](https://doc.rust-lang.org/stable/rust-by-example/custom_types/structs.html)<br>

Structs are a fundamental building block for creating custom data types.
Structs are used to group related data together.

<!-- C-style Struct {{{-->
## C-Style Struct
```rs
struct Point {
    x: f32,
    y: f32,
    str: String,
    opt: Option<i32>
}

// Instantiate `Point`
let point_1: Point = Point { x: 5.2, y: 0.4 };
let point_2: Point = Point { x: 10.3, y: 0.2 };

// Struct update syntax
let point_3 = Point { x: 10.3, ..point1 };

// Access fields
println!("Points: {}, {}", point_1.x, point_1.y);
println!("Points: {}, {}", point_2.x, point_2.y);

// Destructuring
let Point { x, y } = point;

// Field init shorthand
let name = String::from("Peter");
let age = 27;
let peter = Person { name, age };

// Print debug struct
println!("{:?}", peter);
```
<!-- }}} -->

<!-- Tuple Struct {{{-->
## Tuple Struct
```rs
// Definition
struct Pair(i32, f32);

// Instantiate
let pair = Pair(1, 0.1);

// Access fields
println!("pair contains {:?} and {:?}", pair.0, pair.1);

// Destructure
let Pair(integer, decimal) = pair;

println!("pair contains {:?} and {:?}", integer, decimal);
```
<!-- }}} -->

<!-- Unit Struct {{{-->
## Unit Struct
```rs
// Unit struct
struct Unit;

// Instantiate unit struct
let _unit = Unit;
```
<!-- }}} -->
