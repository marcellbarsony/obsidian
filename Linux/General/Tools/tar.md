---
id: tar
aliases: []
tags:
  - Linux/General/Tools/tar
links: "[[Linux/General/Tools/tar]]"
---

# tar

[tar](https://man7.org/linux/man-pages/man1/tar.1.html)
is an archiving utility

___

<!-- Usage {{{-->
## Usage

Create an archive from files

```sh
tar -cvf [archive.tar] [file1] [file2]
```

Create a gzip-compressed archive

```
tar -czvf [archive.tar.gz] [directory/]
```

Create a bzip2-compressed archive

```
tar -cjvf [archive.tar.bz2] [directory/]
```

Create an xz-compressed archive

```
tar -cJvf [archive.tar.xz] [directory/]
```

Extract an archive

```
tar -xvf [archive.tar]
```

Extract a compressed archive

```
tar -xzvf [archive.tar.gz]
```

Extract to a specific directory

```
tar -xvf [archive.tar] -C [directory/]
```

List contents of an archive

```
tar -tvf [archive.tar]
```

Extract specific files

```
tar -xvf [archive.tar] [file1] [file2]
```

___
<!-- }}} -->
