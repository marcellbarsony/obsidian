# User info

## whoami

The `whoami` command displays the currently logged in user on the system by
examining the `/etc/passwd` file.

- [Wikipedia - whoami](https://en.wikipedia.org/wiki/Whoami)
- [IBM - whoami command](https://www.ibm.com/docs/ssw_aix_72/w_commands/whoami.html)

Check the currently logged in user on the system

```sh
whoami
```

## id

Display the system identifications of a specified user.

- [Cyberciti - Linux/Unix id Command Examples](https://www.cyberciti.biz/faq/unix-linux-id-command-examples-usage-syntax/)
- [IBM - id Command](https://www.ibm.com/docs/en/aix/7.3.0?topic=i-id-command)

Find a user’s UID (user ID) or GID (group ID) and other information

```sh
# Syntax
id [Username] id [options]

# Current user
id

# Spicify a user
id -u {user}
```

## Home directory

Investigate the user's home directory

```sh
/home/{username}/
```

## Shell history

Check the user's shell history

```sh
~/.bash-history`
```

## Clipboard data
