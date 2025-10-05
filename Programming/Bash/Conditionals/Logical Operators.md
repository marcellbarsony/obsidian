---
id: Logical Operators
aliases: []
tags: []
---

# Logical Operators

## ; Operator

The command after the `;` will run irrespective the exit status of the first
command

```sh
echo "Hello there." ; echo "General Kenobi"
```

## & Operator

The `&` operator executes `command1` in the background and `command2` starts
running in the foreground, without waiting for `command1` to exit

```sh
command1 & command2
```

## && Operator

The folder `/tmp/bak` is created. If it succeeds and returns with a `0` exit
status, then the `cp` command is executed. The command after `&&` only runs if
the one before ran with a `0` exit code

```sh
mkdir /tmp/bak && cp test.txt /tmp/bak/
```

If the `ping` command returns with exit code `0`, then `google.com reachable`
would be echoed to the screen

```sh
HOST="google.com"
ping -c 1 $HOST && echo "$HOST reachable"
```

## || Operator

The command following the double pipe (`||`) will only execute if the previous
command fails. Only one command can successfully execute.

```sh
cp test.txt /tmp/bak/ || cp test.txt /tmp
```

```sh
HOST="google.com"
ping -c 1 $HOST || echo "$HOST unreachable"
```

If the ping command fails, then `google.com unreachable` would be echoed to the
screen
