# System files

<!-- /etc/passwd {{{-->
## /etc/passwd

The `/etc/passwd` file contains essential information required during login.

### Sources

- [Ciberciti - Understanding /etc/passwd file format](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/)
- [IBM - Using the /etc/passwd file](https://www.ibm.com/docs/fi/ssw_aix_71/security/passwords_etc_passwd_file.html)

### File format

```sh
oracle:x:1021:1020:OracleUser:/data/network/oracle:/bin/bash
```

- `Username`: The user's username between 1 and 32 characters
- `Password`: `x` indicates an encrypted and salted passsword stored in
  [/etc/shadow](https://www.cyberciti.biz/faq/understanding-etcshadow-file/)
- `User ID`: The [User Identifier](https://en.wikipedia.org/wiki/User_identifier)
  (UID) of the user
- `Group ID`: The primary [Group Identifier](https://en.wikipedia.org/wiki/Group_identifier)
  (GID) of the user, stored in the [/etc/group](https://www.cyberciti.biz/faq/understanding-etcgroup-file/)
- `User ID info (GECOS)`: Comment field to add extra infromatin about the users
- `Home directory`: The absolute path to the user's home directory
- `Command/shell`: The absolute path of a command or a shell of the user

### Commands

Search for username(s)
```sh
# Search for a username
grep username /etc/passwd
grep -w '^usermame' /etc/passwd

# Search for multiple usernames
grep -E -w '^(root|username|www-data)' /etc/passwd
```

Get entries
```sh
getent passwd
getent passwd {user1} {user2}
getent passwd username
getent passwd username root
```

Details of the file
```sh
stat /etc/passwd
```
<!-- }}} -->

<!-- /etc/shadow {{{-->
## /etc/shadow

The `/etc/shadow` file is a text-based password file that stores each user's
  salted password hash.

### Sources

- [Cyberciti - Understanding /etc/shadow file format on Linux](https://www.cyberciti.biz/faq/understanding-etcshadow-file/)
<!-- }}} -->
