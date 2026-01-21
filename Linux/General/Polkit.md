---
id: Polkit
aliases: []
tags:
  - Linux/General/Polkit
---


# Polkit

[Polkit](https://en.wikipedia.org/wiki/Polkit) (*PolicyKit*)
is a component for controlling system-wide privileges
in Unix-like operating systems

**Polkit** is an authorization service
that allows user software and system components
to communicate with each other
if the user software is authorized to do so

**Polkit** works with two groups of files

1. actions/policies (`/usr/share/polkit-1/actions`)
2. rules (`/usr/share/polkit-1/rules.d`)

**Polkit** comes with three additional programs

1. [pkexec](https://linux.die.net/man/1/pkexec) -
   Run a program with the rights of another user or with `root` rights

```sh
pkexec -u <user> <command>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> pkexec -u root id
> ```
> ```sh
> uid=0(root) gid=0(root) groups=0(root)
> ```
>
<!-- }}} -->

2. [pkaction](https://linux.die.net/man/1/pkaction) -
   Display actions

```sh
pkaction --action-id action
```

3. [pkcheck](https://linux.die.net/man/1/pkcheck) -
   Check if a process is authorized for a specific action

```sh
pkcheck --action-id action {--process { pid | pid,pid-start-time } | --system-bus-name busname}
```

___
