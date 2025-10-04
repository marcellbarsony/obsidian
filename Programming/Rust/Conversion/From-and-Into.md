# From and Into

<!-- From {{{-->
## From

The `From` trait allows for a type to define how to create itself
from another type.

```rs
// Convert a `str` into `String`
let my_str = "hello";
let my_string = String::from(my_str);
```

```rs
use std::convert::From;

#[derive(Debug)]
struct Number {
    value: i32,
}

impl From<i32> for Number {
    fn from(item: i32) -> Self {
        Number { value: item }
    }
}

fn main() {
    let num = Number::from(30);
    println!("My number is {:?}", num);
}
```
<!--}}}-->

<!-- Into {{{-->
## Into

The `Into` trait is the reciprocal of the `From` trait.

```rs
use std::convert::Into;

#[derive(Debug)]
struct Number {
    value: i32,
}

impl Into<Number> for i32 {
    fn into(self) -> Number {
        Number { value: self }
    }
}

fn main() {
    let int = 5;
    let num: Number = int.into();
    println!("My number is {:?}", num);
}
```
<!--}}}-->
