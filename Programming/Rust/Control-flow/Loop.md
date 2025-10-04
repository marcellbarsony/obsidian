# Loop

```rs
let mut counter: i32 = 0;

let result = loop {
    counter += 1;
    if counter == 10 {
        // Break loop & return counter
        break counter;
    }
};
```

## Nesting and labels

```rs
fn main() {
    'outer: loop {
        'inner: loop {
            break 'outer;
        }
    }
}
```
