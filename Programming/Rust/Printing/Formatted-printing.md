# Formatted printing

Printing is handled by a series of macros defined in `std::fmt`

- `format!`: write formatted text to `String`
- `print!`: same as `format!` but the text is printed to the console (io::stdout).
- `println!`: same as `print!` but a newline is appended.
- `eprint!`: same as `print!` but the text is printed to the standard error (io::stderr).
- `eprintln!`: same as `eprint!` but a newline is appended.

```rs
    println!("{} days", 31);

    // Positional parameters
    println!("{0}, this is {1}. {1}, this is {0}", "Alice", "Bob");

    // Named arguments
    println!("{subject} {verb} {object}",
             object="the lazy dog",
             subject="the quick brown fox",
             verb="jumps over");

    // Format characters
    println!("Base 10:               {}",   69420); // 69420
    println!("Base 2 (binary):       {:b}", 69420); // 10000111100101100
    println!("Base 8 (octal):        {:o}", 69420); // 207454
    println!("Base 16 (hexadecimal): {:x}", 69420); // 10f2c

    // Right-justify text
    println!("{number:>5}", number=1); // "    1"
    // Numbers with extra zeroes,
    println!("{number:0>5}", number=1); // 00001
    // left-adjust by flipping the sign
    println!("{number:0<5}", number=1); // 10000
    // Named arguments in the format specifier
    println!("{number:0>width$}", number=1, width=5);
```

Only types that implement the `fmt::Display` trait can be formatted with `{}`.

- `fmt::Debug`: Uses the `{:?}` marker
- `fmt::Display`: Uses the `{}` marker
