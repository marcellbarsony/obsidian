# Variables

Variable names can contain characters in the range [A-Z][0-9] and underscores.

Variables cannot start with
- a digit 0-9
- two underscores
- an underscore followed by a capital A-Z

### Declaration & Initialization

```c
int x;       // Declaration
x = 123;     // Initialization
int x = 123; // Declaration + Initialization
```

### Data types

| Integer                | Size (B) | Range                                       | Format specifier |
| ---------------------- | -------- | ------------------------------------------- | ---------------- |
| int                    | 4        | -2,147,483,648 - 2,147,483,647              | %d               |
| short int              | 2        |        -32,768 - 32,767                     | %hd              |
| long int               | 4        | -2,147,483,648 - 2,147,483,647              | %ld              |
| long long int          | 8        |        -(2^63) - (2^63)-1                   | %lld             |
| unsigned int           | 4        |              0 - 4,294,967,295              | %u               |
| unsigned short int     | 2        |              0 - 65,535                     | %hu              |
| unsigned long int      | 4        |              0 - 4,294,967,295              | %lu              |
| unsigned long long int | 8        |              0 - 18,446,744,073,709,551,615 | %llu             |
| float                  | 4        |        1.2E-38 - 3.4E+38                    | %f               |
| double                 | 8        |       1.7E-308 - 1.7E+308                   | %lf              |
| long double            | 1        |      3.4E-4932 - 1.1E+4932                  | %Lf              |

| Character              | Size (B) | Range                                       | Format specifier |
| ---------------------- | -------- | ------------------------------------------- | ---------------- |
| signed char            | 1        |           -128 - 127                        | %c               |
| unsigned char          | 1        |              0 - 255                        | %c               |
| character array        | 1 / char |                                             | %s               |

| Boolean                | Size (B) | Range                                       | Format specifier |
| ---------------------- | -------- | ------------------------------------------- | ---------------- |
| bool                   | 1        |              0 - 1 (non-zero)               | %d               |

#### Examples

```c
int x = 123;         // Integer
short int i = 69420; // Short integer

float f = 4.20;  // Float
double d = 3.14; // Double
long l = 42069;  // Long

char a = 'a';       // Character
char abc[] = "ABC"; // Character array

bool e = 1; // Boolean
```

```c
printf("Number: %f\n", f);    // Float
printf("Number: %.2f\n", f);  // Decimal precision
printf("Number: %8f\n", f);   // Field width
printf("Number: %8.2f\n", f); // Field width + Decimal precision
printf("Number: %-f\n", f);   // Left align
printf("Number: %-.3f\n", f); // Left align + Decimal precision
```

