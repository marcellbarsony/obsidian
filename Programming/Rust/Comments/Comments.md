# Comments

[Comments - Rust By Example](https://doc.rust-lang.org/stable/rust-by-example/hello/comment.html)

Line comment

```rs
// Example line comment
```

Block comment

```rs
/*
 * This is another type of comment, a block comment.
 * Line comments are the recommended comment style.
 * Block comments are useful for temporarily disabling chunks of code.
 */

/*
Note: The column of `*` isn't required
It's for styling purposes only
*/
```

In-line comment

```rs
// In-line comments
let x = 5 + /* 90 + */ 5;
println!("Is `x` 10 or 100? x = {}", x);
```
