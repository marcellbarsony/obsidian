# Wildcards

A wildcard is a character or string used for matching file and directory names.
Globbing expands the wildcard pattern into a list of files and/or directories
(paths).

Wildcards can be used with most commands (`ls`, `rm`, `cp`, etc.)

## \*

Matches zero or mare characters

- \*.txt
- a\*
- a\*.txt

## ?

- Matches exactly one character
- ?.txt
- a?
  a?.txt

## \

- Escape character
- Match all files that end with a question mark: \*\?
