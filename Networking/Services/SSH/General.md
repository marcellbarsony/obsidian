---
id: SSH
aliases:
  - Secure Shell
tags:
  - Networking/Services/SSH/General
port:
  - 22
links: "[[Networking/Services/General]]"
---

<!-- SSH {{{-->
# SSH

**SSH** ([Secure Shell](https://en.wikipedia.org/wiki/Secure_Shell))
is a client-server model network protocol that allows a secure way to acces a
computers remotely via password authentication or passwordless
[[#Public Key Authentication]].

___

<!-- }}} -->

<!-- Public Key Authentication {{{-->
## Public Key Authentication

[SSH Public Key Authentication](https://www.ssh.com/academy/ssh/public-key-authentication)
uses [asymmetric cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)
with a [[#Private Key]] and a corresponding [[#Public Key]].

Prior to the authentication process:

1. The user generates a key pair

2. The [[#Public Key]] is copied to the server's `~/.ssh/authorized_keys`

During the authentication process:

1. Client initiate SSH connection to the server

2. Server sends a cryptographic challenge based on the stored [[#Public Key]]

3. Client signs the challenge with its [[#Private Key]]

4. Server verifies the signature using the [[#Public Key]]


> [!example]-
>
> ![[ssh-pka-light.png]]

<!-- Key Pairs {{{-->
### Key Pairs

#### Private Key

The **private key** is generated and stored locally,
and often secured with a passphrase.

Possession of the private key allows a user to authenticate themselves
to a server that recognizes the matching public key.

#### Public Key

The **public key** is copied to the SSH server(s).
Anyone with a copy of the public key can encrypt data which can be
be decrypted by the server(s).

If a server receives a public key from a trustworthy user,
it marks the key as authorized in its [authorized_keys file](https://www.ssh.com/academy/ssh/authorized-keys-file)
as an [authorized key](https://www.ssh.com/academy/ssh/authorized-key).

<!-- }}} -->

___

<!-- }}} -->

<!-- Port Forwarding {{{-->
## Port Forwarding

> [!todo]

https://iximiuz.com/en/posts/ssh-tunnels/

> [!example]-
>
> ![[ssh-port-forwarding.png]]

> [!example]-
>
> ![[ssh-local-port-forwarding.png]]

> [!example]-
>
> ![[ssh-local-port-forwarding-bastion.png]]

> [!example]-
>
> ![[ssh-remote-port-forwarding.png]]

> [!example]-
>
> ![[ssh-remote-port-forwarding-home-network.png]]

___

<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

<!-- Default Configuration {{{-->
### Default Configuration

The [sshd config](https://www.ssh.com/academy/ssh/sshd_config) file has only
a few settings configured by default

> [!example]-
>
> ```sh
> cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
> ```
> ```sh
> Include /etc/ssh/sshd_config.d/*.conf
> ChallengeResponseAuthentication no
> UsePAM yes
> X11Forwarding yes
> PrintMotd no
> AcceptEnv LANG LC_*
> Subsystem       sftp    /usr/lib/openssh/sftp-server
> ```

<!-- }}} -->

<!-- Dangerous Settings {{{-->
### Dangerous Settings

Misconfigurations can make the SSH server vulnerable to attacks

> [!danger]-
>
> | Setting                      | Description                                |
> | ---------------------------- | ------------------------------------------ |
> | `PasswordAuthentication yes` | Allows password-based authentication       |
> | `PermitEmptyPasswords yes`   | Allows the use of empty passwords          |
> | `PermitRootLogin yes`        | Allows to log in as the root user          |
> | `Protocol 1`                 | Uses an outdated version of encryption     |
> | `X11Forwarding yes`          | Allows X11 forwarding for GUI applications |
> | `AllowTcpForwarding yes`     | Allows forwarding of TCP ports             |
> | `PermitTunnel`               | Allows tunneling                           |
> | `DebianBanner yes`           | Displays a specific banner when logging in |
>
> > [!warning]
> >
> > Allowing password authentication allows to brute-force
> > a known username for possible passwords

<!-- }}} -->

___

<!-- }}} -->
