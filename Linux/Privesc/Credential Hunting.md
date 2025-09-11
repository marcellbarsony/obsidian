---
id: Credential Hunting
aliases: []
tags: []
---

# Credential Hunting

Look for exposed credentials in configuration files, log files, and user history
files.

## Home directory

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' ~/* -R
```

<!-- Shell {{{-->
## Shell

### Bash

Bash history

```sh
cat ~/.bash_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

### Zsh

Zsh history

```sh
cat ~/.zsh_history | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```
<!-- }}} -->

<!-- Environment Variables {{{-->
## Environment Variables

Environment Variables

```sh
printenv | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```

```sh
(env || set) 2>/dev/null
```
<!-- }}} -->

<!-- Web App Source Code {{{-->
## Web App Source Code

Web Server root (`/var/www/`)

```sh
grep -iE 'user.*|pass.*|key.*|secret.*|api.*' /var/www/* -R
```

```sh
find /var/www/ -type f -exec cat {} + | grep -iE 'user.*|pass.*|key.*|secret.*|api.*'
```
<!-- }}} -->
