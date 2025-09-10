---
id: Filter
aliases: []
tags:
  - Linux/Files-directories
  - Linux/Tools
links: "[[Files-Directories]]"
---

# Filter contents

<!-- Pagers {{{-->
## Pagers

### More

Read a file with `more` from STDIN

```sh
cat /etc/passwd | more
```

### Less

Read a file with `less`

```sh
less /etc/passwd
```
___
<!-- }}} -->

<!-- Partial readers {{{-->
## Partial readers

### Head

Read the first 10 lines of a file

```sh
head /etc/passwd
```

### Tail

Read the last 10 lines of a file

```sh
tail /etc/passwd
```
___
<!-- }}} -->

<!-- Awk {{{-->
## Awk

Pattern scanning and processing language

```sh
# Print first column of a file
awk '{print $2}' file.txt

# Print second column of a file
awk '{print $2}' file.txt
```
<!-- }}} -->

<!-- Column {{{-->
## Column

Format output into multiple columns

```sh
# Align .csv data to columns
column -t -s, file.csv

# Example
cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | column -t
```
<!-- }}} -->

<!-- Cut {{{-->
## Cut

Remove sections from each line of files by delimiters

```sh
# Get the first column
cut -f1 file.txt

# Get the first column (csv)
cut -d',' -f1 file.csv

# Example
cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1
```
<!-- }}} -->

<!-- Grep {{{-->
## Grep

Search for a pattern

```sh
# Search for a pattern
cat /etc/passwd | grep "/bin/bash"

# Search for a pattern (case-insensitive)
cat /etc/passwd | grep -i "/bin/bash"

# Exclude pattern
cat /etc/passwd | grep -v "false\|nologin"
```
<!-- }}} -->

<!-- Sed {{{-->
## Sed

Stream editor for filtering and transforming text (search and replace)

```sh
# Repleace `apple` with `orange`
sed 's/apple/orange/g' file.txt

# Example
cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}' | sed 's/bin/HTB/g'
```
<!-- }}} -->

<!-- Sort {{{-->
## Sort

Sort lines of text of files

```sh
# Sort alphabetically
cat /etc/passwd | sort

# Sort numerically
sort -n numbers.txt
```
<!-- }}} -->

<!-- Tr {{{-->
## Tr

Translate, replace or delete characters

```sh
# Convert lowercase to uppercase
tr 'a-z' 'A-Z' < file.txt

# Example
cat /etc/passwd | grep -v "false\|nologin" | tr ":" " "
```
<!-- }}} -->

<!-- wc {{{-->
## wc

```sh
# Count lines
wc -l

# Count characters
wc -m

# Count words
wc -w

# Example
cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}' | wc -l
```
<!-- }}} -->
