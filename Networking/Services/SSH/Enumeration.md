---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SSH/Enumeration
links: "[[SSH]]"
---

# Enumeration

___

<!-- Identify Server {{{-->
## Identify Server

[[Nmap]] — Identify SSH server on a host

```sh
nmap -p 22 <target> -oA ssh-identify
```

[[Nmap]] — Identify supported authentication methods

```sh
nmap --script ssh-auth-methods --script-args="ssh.user=<username>" -p 22 <target> -oA ssh-script-ssh-auth-methods
```

___

<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

[[Netcat|netcat]] — SSH banner grabbing

```sh
ncat -vn <target> 22
```

> [!info]-
>
> - `-v`: Set verbosity level
> - `-n`: Do not resolve hostnames via DNS

> [!tip]-
>
> Banners start with the version number by default
>
> - `SSH-1.99-OpenSSH_3.9p1`: Version `3.9p1`
>   and using both protocol version SSH-1 and SSH-2
>
> - `SSH-2.0-OpenSSH_8.2p1`: Version `8.2p1`
>   and using SSH-2

<!-- Example {{{-->
> [!example]-
>
> ```sh
> netcat 10.10.10.10 22
> ```
<!-- }}} -->

___

<!-- }}} -->

<!-- Public Key {{{-->
## Public Key

[ssh-keyscan](https://man.openbsd.org/ssh-keyscan.1) —
Fetch the server's RSA public SSH host key

```sh
ssh-keyscan -t rsa  -p <target>
```
___
<!-- }}} -->

<!-- Cipher Algorithms {{{-->
## Cipher Algorithms

Enumerate the algorithms the target server offers

[[Nmap]] ([ssh2-enum-algos](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html))

```sh
nmap -p 22 -n -sV --script ssh2-enum-algos -oA ssh-scripts-algos
```

[sslscan](https://github.com/rbsec/sslscan) —
Test SSL/TLS enabled services to discover supported cipher suites

```sh
sslscan :22
```

___
<!-- }}} -->

<!-- Fuzzing {{{-->
## Fuzzing

Fuzzing the SSH service could help to find vulnerabilities

[[Metasploit]] —
SSH 2.0 Version Fuzzer (*[ssh_version_2](https://www.rapid7.com/db/modules/auxiliary/fuzzers/ssh/ssh_version_2/)*)

<!-- Example {{{-->
> [!example]-
>
> ```sh
> msfconsole
> ```
> ```sh
> use auxiliary/fuzzers/ssh/ssh_version_2
> ```
> ```sh
> set RHOSTS
> ```
> ```sh
> run
> ```
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

Checks the client and server-side configuration

Install [SSH Audit](https://github.com/jtesta/ssh-audit)

> [!example]-
>
> ```sh
> git clone https://github.com/jtesta/ssh-audit.git
> ```
> ```sh
> cd ssh-audit
> ```

Run [SSH Audit](https://github.com/jtesta/ssh-audit)

```sh
./ssh-audit.py <target>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ./ssh-audit.py 10.129.14.132
> ```
>
> ```sh
> # general
> (gen) banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
> (gen) software: OpenSSH 8.2p1
> (gen) compatibility: OpenSSH 7.4+, Dropbear SSH 2018.76+
> (gen) compression: enabled (zlib@openssh.com)                                   
>
> # key exchange algorithms
> (kex) curve25519-sha256                     -- [info] available since OpenSSH 7.4, Dropbear SSH 2018.76                            
> (kex) curve25519-sha256@libssh.org          -- [info] available since OpenSSH 6.5, Dropbear SSH 2013.62
> (kex) ecdh-sha2-nistp256                    -- [fail] using weak elliptic curves
>                                             `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
> (kex) ecdh-sha2-nistp384                    -- [fail] using weak elliptic curves
>                                             `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
> (kex) ecdh-sha2-nistp521                    -- [fail] using weak elliptic curves
>                                             `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
> (kex) diffie-hellman-group-exchange-sha256 (2048-bit) -- [info] available since OpenSSH 4.4
> (kex) diffie-hellman-group16-sha512         -- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73
> (kex) diffie-hellman-group18-sha512         -- [info] available since OpenSSH 7.3
> (kex) diffie-hellman-group14-sha256         -- [info] available since OpenSSH 7.3, Dropbear SSH 2016.73
>
> # host-key algorithms
> (key) rsa-sha2-512 (3072-bit)               -- [info] available since OpenSSH 7.2
> (key) rsa-sha2-256 (3072-bit)               -- [info] available since OpenSSH 7.2
> (key) ssh-rsa (3072-bit)                    -- [fail] using weak hashing algorithm
>                                             `- [info] available since OpenSSH 2.5.0, Dropbear SSH 0.28
>                                             `- [info] a future deprecation notice has been issued in OpenSSH 8.2: https://www.openssh.com/txt/release-8.2
> (key) ecdsa-sha2-nistp256                   -- [fail] using weak elliptic curves
>                                             `- [warn] using weak random number generator could reveal the key
>                                             `- [info] available since OpenSSH 5.7, Dropbear SSH 2013.62
> (key) ssh-ed25519                           -- [info] available since OpenSSH 6.5
>
> ...SNIP...
> ```
<!-- }}} -->

___

<!-- }}} -->

<!-- Usernames {{{-->
## Usernames

[[Metasploit]] —
SSH Username Enumeration
([ssh_enumusers](https://www.rapid7.com/db/modules/auxiliary/scanner/ssh/ssh_enumusers/))

```sh
use auxiliary/scanner/ssh/ssh_enumusers
```

<!-- Info {{{-->
> [!info]-
>
> The default action sends a malformed (*corrupted*)
> `SSH_MSG_USERAUTH_REQUEST` packet using
> [[General#Public Key Authentication|Public Key Authentication]]
> (*must be enabled*) to enumerate users
>
> On some versions of OpenSSH under some configurations,
> OpenSSH will return a `permission denied` error
> for an invalid user faster than for a valid user,
> creating an opportunity for a timing attack to enumerate users
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Use a malformed packet or timing attack to enumerate users
>
> ```sh
> msf > use auxiliary/scanner/ssh/ssh_enumusers
> msf auxiliary(ssh_enumusers) > show actions
>     ...actions...
> msf auxiliary(ssh_enumusers) > set ACTION < action-name >
> msf auxiliary(ssh_enumusers) > show options
>     ...show and set options...
> msf auxiliary(ssh_enumusers) > run
> ```
<!-- }}} -->

___

<!-- }}} -->
