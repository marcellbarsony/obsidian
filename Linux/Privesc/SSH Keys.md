---
id: SSH Keys
aliases: []
tags:
  - Linux/Privesc/SSH-Keys
---

# SSH Keys

___

<!-- Discover SSH Keys {{{-->
## Discover SSH Keys

### User

Check the user's `.ssh/`directory for private SSH keys

```sh
/home/<user>/.ssh/id_rsa
```

Check if the user's private SSH key is readable

```sh
[ -r /home/user/.ssh/id_rsa ] && echo "Readable" || echo "Not readable"
```

### root

Check the `/root` directory for private SSH keys

```sh
/root/.ssh/id_rsa
```

Check if the `root` user's private SSH key is readable

```sh
[ -r /root/.ssh/id_rsa ] && echo "Readable" || echo "Not readable"
```
___
<!-- }}} -->

<!-- Exfiltrate SSH private keys {{{-->
## Exfiltrate SSH private keys

If an SSH private key is readable on the target machine,
it may be possible to exfiltrate it

1. Create an RSA key on the attacker machine

```sh
nvim id_rsa
```

2. Change permissions to be more restrictive

The SSH server may prevent the key from working with lax
(*loose or insecure permissions*)

```sh
chmod 600 id_rsa
```

3. SSH to the target machine with the `-i` flag

```sh
ssh root@<target_ip> -p <target_port> -i id_rsa
```
<!-- }}} -->

<!-- Writable SSH directory {{{-->
## Writeable SSH directory

If an SSH directory is writeable on the target machine, it may be possible to
inject SSH keys

This technique is usually used to gain SSH access after gaining a shell as user

1. **Target**: Check write access to `/.ssh/` directory

```sh
test -w /home/<user>/.ssh && echo "Writable" || echo "Not Writable"
```

2. **Attacker**: Create a new SSH key pair

```sh
ssh-keygen -f key
```

3. **Target**: Place the public key (*`key.pub`*) to the SSH directory

```sh
/home/<user>/.ssh/authorized_keys
```

4. **Attacker**: Connect to the target

```sh
ssh <target_user>@<target_ip> -i key
```
<!-- }}} -->
