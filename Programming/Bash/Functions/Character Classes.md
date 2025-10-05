---
id: Character Classes
aliases: []
tags: []
---

# Character Classes

## Brackets - [ ]

- Matches any of the characters included between the brackets. Matches exactly
  one character.
- `[aeious]` - matches a one-character long filename that is a vowel
- `ca[nt]`
  - can
  - cat
  - candy
  - catch

## [!]

- Matches any of the characters **not** included between the brackets.
- Matches exactly **one** character.
- `[!aeiou]`
  - baseball
  - cricket

## Ranges

Use two characters separated by a hyphen to create a range in character class.

- [a-g]\*
  - matches all files that start with `a`, `b`, `c`, `d`, `e`, `f` or `g`.
- [3-6]\*
  - matches al files that start with `3`, `4`, `5` or `6`.

## Named character classes

`[[:alpha:]]` - Matches **alphabetic** letters `[a-z, A-Z]`

`[[:alnum:]]` - Matches **alphanumeric** characters `[a-z, A-Z, 0-9]`

`[[:digit:]]` - Matches **numeric** characters `[0-9]`

`[[:lower:]]` - Matches **lowercase** letters `[a-z]`

`[[:upper:]]` - Matches **uppercase** letters `[A-Z]`

`[[:space:]]` - Matches **whitespace** _(space, tabs, new line characters)_
