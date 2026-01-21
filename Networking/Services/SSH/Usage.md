---
id: Usage
aliases:
  - Secure Shell
tags:
  - Networking/Services/SSH/Usage
links: "[[SSH]]"
---

# Usage

___

<!-- Authentication {{{-->
## Authentication

Check authentication method

```sh
ssh -v <user>@$target
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ssh -v cry0l1t3@10.129.14.132
> ```
> ```sh
> OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
> debug1: Reading configuration data /etc/ssh/ssh_config 
>
> ...SNIP...
>
> debug1: Authentications that can continue: publickey,password,keyboard-interactive
>
> Enforce password-based authentication
> ```
<!-- }}} -->

Set authentication method to `password`

```sh
ssh <user>@$target -o PreferredAuthentications=password
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
> ```
> ```sh
> OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
> debug1: Reading configuration data /etc/ssh/ssh_config
>
> ...SNIP...
>
> debug1: Authentications that can continue: publickey,password,keyboard-interactive
> debug1: Next authentication method: password
>
> cry0l1t3@10.129.14.132's password:
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Connect {{{-->
## Connect

Connect to a host (*with credentials*)

```sh
ssh <user>@$target
```

Connect to a host (*with private key*)

```sh
echo "<private_key>" > id_rsa
```

```sh
chmod 600 id_rsa
```

```sh
ssh -i id_rsa <user>@$target
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

Connect over a jump host

```sh
ssh -J <first_host> <second_host>
```

<!-- Info {{{-->
> [!info]
>
> - `-J`: Destination — Connect to the target host
>   by first making an ssh connection to the jump host
>   described by destination
<!-- }}} -->

___
<!-- }}} -->
