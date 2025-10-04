# Type alias

Refer to an enum via its alias

```rs
enum VeryVerboseEnumOfThingsToDoWithNumbers {
    Add,
    Subtract,
}

// Create a type alias
type Operations = VeryVerboseEnumOfThingsToDoWithNumbers;

fn main() {
    let x = Operations::Add;
}
```

```rs
enum VeryVerboseEnumOfThingsToDoWithNumbers {
    Add,
    Subtract,
}

impl VeryVerboseEnumOfThingsToDoWithNumbers {
    fn run(&self, x: i32, y: i32) -> i32 {
        match self {
            Self::Add => x + y,
            Self::Subtract => x - y,
        }
    }
}
```
