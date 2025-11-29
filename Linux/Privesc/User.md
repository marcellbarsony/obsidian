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
display the currently logged in user on the system

```sh
whoami
```
<!-- }}} -->

___
<!-- }}} -->

<!-- Group {{{-->
## Group

<!-- id {{{-->
### id

Display the system identifications of a specified user.

- [Cyberciti - Linux/Unix id Command Examples](https://www.cyberciti.biz/faq/unix-linux-id-command-examples-usage-syntax/)
- [IBM - id Command](https://www.ibm.com/docs/en/aix/7.3.0?topic=i-id-command)

Find a user’s
[UID](https://en.wikipedia.org/wiki/User_identifier) (*user ID*) or
[GID](https://en.wikipedia.org/wiki/Group_identifier) (*group ID*)
and other information

```sh
id [Username] id [options]
```

Current user

```sh
id
```

Specific user

```sh
id -u <user>
```

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

<!-- }}} -->

___
<!-- }}} -->
