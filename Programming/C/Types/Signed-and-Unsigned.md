# Signed and Unsigned types

- `signed` types can hold positive and negative values.
- `unsigned` types can hold negative values only.

```c
int a;           // signed
signed int a;    // signed
signed a;        // signed, "shorthand" for "int" or "signed int"
unsigned int b;  // unsigned
unsigned c;      // unsigned, shorthand for "unsigned int"
```

| Type         | Minimum                    | Maximum                    |
| ------------ | -------------------------- | -------------------------- |
| int          | -9,223,372,036,854,775,808 | 9,223,372,036,854,775,807  |
| unsigned int | 0                          | 18,446,744,073,709,551,615 |
