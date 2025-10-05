---
id: case
aliases: []
tags: []
---

# Case Statement

Case statement are an alternative to if statements

- Patterns can include wildcards
- Multiple pattern matching using a pipe

## Syntax

```sh
case "$VAR" in
pattern_1)
    command N
    ;;
pattern_N)
    command N
    ;;
esac
```

> [!example]-
>
>```sh
>case "$1" in
>    start|START)
>      /usr/sbin/sshd
>      ;;
>    stop|STOP)
>      kill $(cat /var/run/sshd.pid)
>      ;;
>    *)
>      echo "Usage: $0 start|stop" ; exit 1
>      ;;
>esac
>```

If the positional parameter (`$1`) equals to _start_, then `/usr/sbind/sshd` is
executed
