# Option enum

```rs
enum Option<T> {
    Some(T),
    None
}

let x: Option<i8> = Some(5);
let y: Option<i8> = None;
let sum  = x.unwrap_or(0) + y.unwrap_or(0);
```
