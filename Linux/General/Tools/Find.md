---
id: Find
aliases:
  - Find Files and Directories
tags:
  - Linux/General/Tools/CLI
links: "[[Files-Directories]]"
---

# Find Files and Directories

## Which

Get the full path of shell commands

```sh
which <command>
```

```sh
which python
```

## Find

Search for files and directories

```sh
find <location> <options>
```

```sh
find . -type f -name "*.conf" -user root -size +20k -newermt 2023-03-03
find . -type d -name dirname 
```

## Locate

Update `locate` database

```sh
sudo updatedb
```

Search for all files with `*.conf` extension

```sh
locate "*.conf"
```
