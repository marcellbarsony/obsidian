---
id: SSH Keys
aliases: []
tags:
  - Linux/Privesc/SSH-Keys
---

# SSH Keys

## Discover SSH Keys

It may be possible to read the `.ssh` directory of a specific user

```sh
/home/<user>/.ssh/id_rsa
```

```sh
/root/.ssh/id_rsa
```

## Copy SSH Keys

Create an RSA key on the attacker machine

```sh
nvim id_rsa
```

Change permissions to be more restrictive as the SSH server may prevent it from
working with lax (loose or insecure permissions)

```sh
chmod 600 id_rsa
```

SSH to the target machine with the `-i` flag

```sh
ssh root@10.10.10.10 -i id_rsa
```

## Writeable SSH directory

Check write access to `/.ssh/` directory

```sh
test -w /home/<user>/.ssh && echo "Writable" || echo "Not Writable"
```

Create a new SSH key pair

```sh
ssh-keygen -f key
```

Place the public key (`key.pub`) to the target machine

```sh
/home/<user>/.ssh/authorized_keys
```
