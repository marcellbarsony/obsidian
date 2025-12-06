---
id: Users & Groups
aliases: []
tags:
  - Linux/General/Users
  - Linux/General/Groups
---

# Users & Groups

<!-- User Management {{{-->
## User Management

<!-- Shadow {{{-->
### Shadow

The `/etc/shadow` file stores encrypted password information
for all user accounts

<!-- }}} -->

<!-- Add User {{{-->
## Add User

[useradd](https://linux.die.net/man/8/useradd) -
Create a new user or update default new user information

```sh
useradd [-m] <user>
```

> [!info]-
>
> - `-m`: Add HOME directory

[passwd](https://linux.die.net/man/1/passwd) -
Update user's authentication

```sh
passwd <user>
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Group Management {{{-->
## Group Management

The `/etc/group` file defines the groups on a system

```sh
cat /etc/group
```

[gpasswd](https://linux.die.net/man/1/gpasswd) —
Add user to a group

```sh
gpasswd -a <user> <group>
```

[groupadd](https://linux.die.net/man/8/groupadd) —
Create a new group

```sh
groupadd <group>
```

[groups](https://linux.die.net/man/1/groups) —
print the groups a user is in

```sh
groups [user]
```

[id](https://linux.die.net/man/1/id) —
Print real and effective user and group IDs
(*`UID` & associated `GID`*)

```sh
id [user]
```

[groupmod](https://linux.die.net/man/8/groupmod) —
Add user to group(s)

```sh
usermod -aG <group>,<group2> <user>
```


> [!todo]

___
<!-- }}} -->

<!-- Execution as root {{{-->
## Execution as root

| Command  | Description |
| -------- | ----------- |
| sudo     | Execute command as a different user. |
| su       | The su utility requests appropriate user credentials via PAM and switches to that user ID. A shell is then executed. |
| useradd  | Creates a new user or update default new user information. |
| userdel  | Deletes a user account and related files. |
| usermod  | Modifies a user account. |
| addgroup | Adds a group to the system. |
| delgroup | Removes a group from the system. |
| passwd   | Changes user password.  |

___
<!-- }}} -->
