---
id: System Files
aliases: []
tags:
  - Linux/Privesc/System-Files
---

# System Files

___

<!-- /etc/passwd {{{-->
## /etc/passwd

[/etc/passwd](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/)
stores essential information required during login

<!-- Resources {{{-->
> [!info]- Resources
>
> - [IBM - Using the /etc/passwd file](https://www.ibm.com/docs/fi/ssw_aix_71/security/passwords_etc_passwd_file.html)
<!-- }}} -->

<!-- Enumeration {{{-->
### Enumeration

Search for a username

```sh
grep username /etc/passwd
```

```sh
grep -w '^usermame' /etc/passwd
```

Search for multiple usernames

```
grep -E -w '^(root|username|www-data)' /etc/passwd
```

[Getent](https://en.wikipedia.org/wiki/Getent) —
Get entries

```sh
getent passwd
```

```sh
getent passwd <user1> <user2>
```

```sh
getent passwd username
```

```sh
getent passwd username root
```

Details of the file

```sh
stat /etc/passwd
```

<!-- }}} -->

<!-- File Format {{{-->
### File Format

```sh
oracle:x:1021:1020:OracleUser:/data/network/oracle:/bin/bash
```

<!-- Info {{{-->
> [!info]-
>
> - `Username`: The user's username between 1 and 32 characters
> - `Password`: `x` indicates an encrypted and salted passsword stored in
>   [/etc/shadow](https://www.cyberciti.biz/faq/understanding-etcshadow-file/)
> - `User ID`: The [User Identifier](https://en.wikipedia.org/wiki/User_identifier)
>   (UID) of the user
> - `Group ID`: The primary [Group Identifier](https://en.wikipedia.org/wiki/Group_identifier)
>   (GID) of the user, stored in the [/etc/group](https://www.cyberciti.biz/faq/understanding-etcgroup-file/)
> - `User ID info (GECOS)`: Comment field to add extra infromatin about the users
> - `Home directory`: The absolute path to the user's home directory
> - `Command/shell`: The absolute path of a command or a shell of the user
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- /etc/shadow {{{-->
## /etc/shadow

[/etc/shadow](https://www.cyberciti.biz/faq/understanding-etcshadow-file/)
stores hashed passwords for user accounts

<!-- Enumeration {{{-->
### Enumeration

<!-- Readability {{{-->
#### Readability

Check if `/etc/shadow` is world-readable (*`644`*)

> [!info]
>
> Default value: `600`

```sh
stat -c "%a %n" /etc/shadow
```

```sh
[ -r /etc/shadow ] && echo "Readable /etc/shadow: YES" || echo "Readable /etc/shadow: NO"
```

> [!tip]
>
> Crack the extracted password hashes with [[Hashcat]]

<!-- }}} -->

<!-- Writeability {{{-->
#### Writeability

Check if `/etc/shadow` is writeable by other users

```sh
[ -w /etc/shadow ] && echo "Writeable /etc/shadow: YES" || echo "Writeable /etc/shadow: NO"
```

> [!tip]
>
> Set or remove passwords, or inject password hashes

<!-- }}} -->

<!-- Ownership {{{-->
#### Ownership

Check if `/etc/shadow` has incorrect ownership —
Other users or services might gain unexpected write access,
enabling lateral movement or privilege escalation

> [!info]
>
> Default value: `root:root /etc/shadow`

```sh
stat -c "%U:%G %n" /etc/shadow
```

```sh
[ "$(stat -c %U:%G /etc/shadow)" != "root:root" ] && echo "Ownership /etc/shadow: Incorrect" || echo "Ownership /etc/shadow: Correct"
```

> [!tip]
>
> Escalate by abusing whatever process/user owns the file
> — e.g., trick a service running as that user into writing to `/etc/shadow`

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
