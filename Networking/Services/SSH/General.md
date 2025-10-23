---
id: SSH
aliases:
  - Secure Shell
tags:
  - Networking/Services/SSH/General
port:
  - 22
links: "[[Services]]"
---

<!-- SSH {{{-->
# SSH

**SSH** ([Secure Shell](https://en.wikipedia.org/wiki/Secure_Shell))
is a client-server model network protocol that allows a secure way to acces a
computers remotely via password authentication or passwordless
[[#Public Key Authentication]].

> [!todo]

___

<!-- }}} -->

<!-- Public Key Authentication {{{-->
## Public Key Authentication

> [!todo]

[public-key authentication](https://serverpilot.io/docs/guides/ssh/public-key-auth/)

using an SSH public/private key pair.


- The server sends its public host key to the client,
  which the client uses to verify the server's identity

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
