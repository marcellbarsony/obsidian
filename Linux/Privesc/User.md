---
id: User Enumeration
aliases: []
tags:
  - Linux/Privesc/User-Enumeration
links: "[[Privesc]]"
---

# User Enumeration

Enumerate current user and group

___

<!-- User {{{-->
## User

<!-- Identify {{{-->
### Identify

[whoami](https://en.wikipedia.org/wiki/Whoami) —
Display the currently logged in user on the system

```sh
whoami
```
<!-- }}} -->

<!-- Home Directories {{{-->
### Home Directories

Discover users and their home directories

```sh
ls /home
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Group {{{-->
## Group

<!-- id {{{-->
### id

Display the system identifications of a specified user

<!-- Resources {{{-->
> [!info]- Resources
>
> - [Cyberciti - Linux/Unix id Command Examples](https://www.cyberciti.biz/faq/unix-linux-id-command-examples-usage-syntax/)
> - [IBM - id Command](https://www.ibm.com/docs/en/aix/7.3.0?topic=i-id-command)
<!-- }}} -->

<!-- Tip {{{-->
> [!tip]
>
> [[Find]] files belonging to a group
>
> ```sh
> find / -group <group_name> 2>/dev/null
> ```
>
> [[Directory & File|Enumerate]] found files
>
<!-- }}} -->


[id](https://linux.die.net/man/1/id) —
Find a user’s
[UID](https://en.wikipedia.org/wiki/User_identifier) (*user ID*) or
[GID](https://en.wikipedia.org/wiki/Group_identifier) (*group ID*)
and other information

```sh
id [Username] id [options]
```

[id](https://linux.die.net/man/1/id) —
Current user

```sh
id
```

[id](https://linux.die.net/man/1/id) —
Specific user

```sh
id -u <user>
```

<!-- }}} -->


___
<!-- }}} -->
