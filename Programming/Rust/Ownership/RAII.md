# RAII

Rust enforces RAII (Resource Acquisition Is Initialization):
whenever an object goes out of scope, its destructor is called
and its owned resources are freed to prevent memory leak bugs.

```rs
fn create_box() {
    // Allocate an integer on the heap
    let _box1 = Box::new(3i32);

    // `_box1` is destroyed here, and memory gets freed
}

fn main() {
    // Allocate an integer on the heap
    let _box2 = Box::new(5i32);

    {
        // Allocate an integer on the heap
        let _box3 = Box::new(4i32);

        // `_box3` is destroyed here, and memory gets freed
    }

    // Creating lots of boxes just for fun
    for _ in 0u32..1_000 {
        create_box();
    }
    // `_box2` is destroyed here, and memory gets freed
}
```
