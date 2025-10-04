# Object files

C files can be compiled to an intermediate representation called object files.
These are compiled machine codes that hasn't been put into an executable yet.

Object files in Unix hav a `.o` extension (on Windows it's `.OBJ`)

```c
clang -c foo.c   # produces foo.o
gcc -c foo.c     # produces foo.o
```
