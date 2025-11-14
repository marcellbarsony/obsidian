---
id: File
aliases: []
tags:
  - Linux/Privesc/File
links: "[[Linux]]"
---

# File Enumeration

___

<!-- File {{{-->
## File

Enumerate a file

```sh
file <file>
```

> [!tip]
>
> Search for [Setuid (SUID)](https://en.wikipedia.org/wiki/Setuid) bit set

___
<!-- }}} -->

<!-- Ownership {{{-->
## Ownership

Display a file's ownership info

```sh
ls -al <file>
```
___
<!-- }}} -->

<!-- Credentials {{{-->
## Credentials

Search a file for credentials

```sh
cat <file> | grep pass*
```

```sh
cat <file> | grep user*
```
___
<!-- }}} -->
