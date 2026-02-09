---
id: zip
aliases: []
tags:
  - Linux/General/Tools/zip
links: "[[Linux/General/Tools/tar]]"
---

# zip

[zip](https://en.wikipedia.org/wiki/ZIP_(file_format))
is an archive file format that supports lossless data compression

___

<!-- Usage {{{-->
## Usage

Create a ZIP archive

```sh
zip [archive.zip] [file1] [file2]
```

Create archive from directory

```sh
zip -r [archive.zip] [directory/]
```

Add files to existing archive

```sh
zip [archive.zip] [newfile.txt]
```

Create archive with compression level

```sh
zip -9 [archive.zip] [files]
```

Create encrypted archive

```sh
zip -e [archive.zip] [files]
```

Exclude files from archive

```sh
zip -r [archive.zip] [directory/] -x "*.log"
```

Update only changed files

```sh
zip -u [archive.zip] [files]
```

Create archive excluding directory

```sh
zip -r [archive.zip] [dir/] -x [dir/subdir/*]
```

Delete file from archive

```sh
zip -d [archive.zip] [file_to_remove]
```

___
<!-- }}} -->
