# Struct Implementation

Implementing methods and associated functions

```rs
impl Person {
    // Associated function (Static method)
    fn new_type(string: String, num: u8) -> Type {
        Type { string, num }
    }

    // Method
    fn set_num(&mut self, num: u8) {
        self.num = num;
    }
```
