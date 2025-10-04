---
id: Permissions
aliases: []
tags:
  - Linux/General/Permissions
links: "[[Filesystem]]"
---

# Premissions

There are three different types of permissions a file or directory can be
assigned:

- (`r`) - Read
- (`w`) - Write
- (`x`) - Execute

| Binary Notation | Binary Repr. | Octal | Premission |
| --------------- | ------------ | ----- | ---------- |
| 4 2 1           | 1 1 1        | 7     | r w x      |
| 4 2 1           | 1 0 1        | 5     | r - x      |
| 4 2 1           | 1 0 0        | 4     | r - -      |

These permissions can be set for the `owner`, `group` and `others`

> [!example]-
>
>```sh
>ls -l /etc/passwd
>
>- rwx rw- r--   1 root root 1641 May  4 23:42 /etc/passwd
>- --- --- ---   |  |    |    |   |__________|
>|  |   |   |    |  |    |    |        |_ Date
>|  |   |   |    |  |    |    |__________ File Size
>|  |   |   |    |  |    |_______________ Group
>|  |   |   |    |  |____________________ User
>|  |   |   |    |_______________________ Number of hard links
>|  |   |   |_ Permission of others (read)
>|  |   |_____ Permissions of the group (read, write)
>|  |_________ Permissions of the owner (read, write, execute)
>|____________ File type (- = File, d = Directory, l = Link, ... )
>```

## Change permissions

Change permissions with the `chmod` command

```sh
# Apply read permissions for all users
chmod a+r file.txt

# Apply read permissions to other users and execute to group
chmod 754 file.txt
```

## Change owner/group

Change owner and/or group of a file

```sh
chown <user>:<group> <file/directory>
```

> [!example]-
>
>```sh
>chown marci:marci file.txt
>```

## SUID & SGID

**Set User ID** (`SUID`) and **Set Group ID** (`SGID`) bits enabling users to
run programs with the privilege of another user or group.

The presence of these permissions is indicated by an `s` in place of the usual
`x` in the file's permission set.

```sh
# SUID
-rwsr-xr-x. 1 root root 33544 Dec 13  2022 /usr/bin/passwd

# SGID
drwxrws---. 2 marci marci  69 Apr  7  2022 my_articles
```

When a program with the `SUID` or `SGID` bit set is executed, it runs with the
permissions of the file's owner or group, rather than the user who launched.

## Sticky Bit

Sticky bits are like locks on files within shared spaces. When set on a
directory, the sticky bit adds an extra layer of security, ensuring that only
certain individuals can modify or delete files, even if others have access to
the directory.

> [!example]
>
>```sh
>ls -l
>```
>
>```sh
>drw-rw-r-t 3 marci marci   4096 Jan 12 12:30 file-1.txt
>drw-rw-r-T 3 marci marci   4096 Jan 12 12:32 file-2.txt
>```

> [!info]-
>
>- `t`: Exucute (`x`) permissions have been set
>- `T`: All other users don't have execute (`x`) permissions
