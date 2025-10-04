# Lifetimes

A lifetime is a construct the borrow checker uses to ensure all borrows are
valid.

- A lifetime begins when a variable is created (initilized)
- A lifetime ends and ends when a variable is destroyed.

## Explicit annotation

```rs
foo<'a, 'b>
```
