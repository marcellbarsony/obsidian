---
id: unzip
aliases: []
tags:
  - Linux/General/Tools/unzip
links: "[[Linux/General/Tools/unzip]]"
---

# zip

[uzip](https://en.wikipedia.org/wiki/ZIP_(file_format))
is an archive file format that supports lossless data compression

<!-- Info {{{-->
> [!info]- Resources
>
> [Linux Command Library](https://linuxcommandlibrary.com/man/unzip)
>
<!-- }}} -->

___

<!-- Usage {{{-->
## Usage

Extract files to current directory

```sh
unzip [archive.zip]
```

Extract to specific directory

```sh
unzip [archive.zip] -d [/path/to/directory]
```

List contents without extracting

```sh
unzip -l [archive.zip]
```

Extract specific files

```sh
unzip [archive.zip] [file1.txt] [file2.txt]
```

Extract with pattern

```sh
unzip [archive.zip] "*.txt"
```

Extract quietly (minimal output)

```sh
unzip -q [archive.zip]
```

Extract and overwrite existing files

```sh
unzip -o [archive.zip]
```

Test archive integrity

```sh
unzip -t [archive.zip]
```

Extract preserving directory structure

```sh
unzip [archive.zip]
```

___
<!-- }}} -->
