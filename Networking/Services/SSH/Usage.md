---
id: Usage
aliases:
  - Secure Shell
tags:
  - Networking/Services/SSH/Usage
links: "[[SSH]]"
---

# Usage

<!-- Connect {{{-->
## Connect

Connect to a host

```sh
ssh <user>@<target>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ssh bob@10.10.10.10 -i id_rsa -p 1234
> ```
>
> - `-i id_rsa`: Specify private key (*optional*)
> - `-p 1234`: Specify target port (*optional*)
<!-- }}} -->

Connect with private key

```sh
ssh -i <path/to/private_key> <user>@<target>
```

<!-- Authenticate {{{-->
### Authenticate

Check authentication method

```sh
ssh -v <user>@<target>
```

> [!example]-
>
> ```sh
> ssh -v cry0l1t3@10.129.14.132
> ```
> ```sh
> OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
> debug1: Reading configuration data /etc/ssh/ssh_config 
> ...SNIP...
> debug1: Authentications that can continue: publickey,password,keyboard-interactive
>
> Enforce password-based authentication
> ```

Set authentication method to `password`

```sh
ssh <user>@<target> -o PreferredAuthentications=password
```

> [!example]-
>
> ```sh
> ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
> ```
> ```sh
> OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
> debug1: Reading configuration data /etc/ssh/ssh_config
> ...SNIP...
> debug1: Authentications that can continue: publickey,password,keyboard-interactive
> debug1: Next authentication method: password
>
> cry0l1t3@10.129.14.132's password:
> ```

<!-- }}} -->

___

<!-- }}} -->
