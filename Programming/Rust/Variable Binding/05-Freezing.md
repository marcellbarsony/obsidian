# Freezing

When data is bound by the same name immutably, it also freezes.
Frozen data can't be modified until the immutable binding goes out of scope:

```rs
fn main() {
    let mut _mutable = 7i32;

    {
        // Shadowing by immutable `_mutable`
        let _mutable = _mutable;

        _mutable = 50; // Error!
        // `_mutable` is frozen in this scope
    }

    _mutable = 3; // Ok!
    // `_mutable` is not frozen in this scope
}
```
