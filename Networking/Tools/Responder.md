---
id: Responder
aliases: []
tags:
  - Networking/Tools/Responder
links: "[[Networking/Tools/General]]"
---

# Responder

[Responder](https://github.com/lgandx/Responder)
is a LLMNR, NBT-NS, and MDNS poisoner
with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication servers

___

<!-- Install {{{-->
## Install

[Kali Tools](https://www.kali.org/tools/responder/)

```sh
sudo apt install responder
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Help

```sh
responder -h
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> responder -h
> ```
> ```sh
> Options:
>   --version             show program's version number and exit
>   -h, --help            show this help message and exit
>   -A, --analyze         Analyze mode. This option allows you to see NBT-NS,
>                         BROWSER, LLMNR requests without responding.
>   -I eth0, --interface=eth0
>                         Network interface to use, you can use 'ALL' as a
>                         wildcard for all interfaces
>   -i 10.0.0.21, --ip=10.0.0.21
>                         Local IP to use (only for OSX)
>   -6 2002:c0a8:f7:1:3ba8:aceb:b1a9:81ed, --externalip6=2002:c0a8:f7:1:3ba8:aceb:b1a9:81ed
>                         Poison all requests with another IPv6 address than
>                         Responder's one.
>   -e 10.0.0.22, --externalip=10.0.0.22
>                         Poison all requests with another IP address than
>                         Responder's one.
>   -b, --basic           Return a Basic HTTP authentication. Default: NTLM
>   -d, --DHCP            Enable answers for DHCP broadcast requests. This
>                         option will inject a WPAD server in the DHCP response.
>                         Default: False
>   -D, --DHCP-DNS        This option will inject a DNS server in the DHCP
>                         response, otherwise a WPAD server will be added.
>                         Default: False
>   -w, --wpad            Start the WPAD rogue proxy server. Default value is
>                         False
>   -u UPSTREAM_PROXY, --upstream-proxy=UPSTREAM_PROXY
>                         Upstream HTTP proxy used by the rogue WPAD Proxy for
>                         outgoing requests (format: host:port)
>   -F, --ForceWpadAuth   Force NTLM/Basic authentication on wpad.dat file
>                         retrieval. This may cause a login prompt. Default:
>                         False
>   -P, --ProxyAuth       Force NTLM (transparently)/Basic (prompt)
>                         authentication for the proxy. WPAD doesn't need to be
>                         ON. This option is highly effective. Default: False
>   -Q, --quiet           Tell Responder to be quiet, disables a bunch of
>                         printing from the poisoners. Default: False
>   --lm                  Force LM hashing downgrade for Windows XP/2003 and
>                         earlier. Default: False
>   --disable-ess         Force ESS downgrade. Default: False
>   -v, --verbose         Increase verbosity.
>   -t 1e, --ttl=1e       Change the default Windows TTL for poisoned answers.
>                         Value in hex (30 seconds = 1e). use '-t random' for
>                         random TTL
>   -N ANSWERNAME, --AnswerName=ANSWERNAME
>                         Specifies the canonical name returned by the LLMNR
>                         poisoner in its Answer section. By default, the
>                         answer's canonical name is the same as the query.
>                         Changing this value is mainly useful when attempting
>                         to perform Kerberos relaying over HTTP.
>   -E, --ErrorCode       Changes the error code returned by the SMB server to
>                         STATUS_LOGON_FAILURE. By default, the status is
>                         STATUS_ACCESS_DENIED. Changing this value permits to
>                         obtain WebDAV authentications from the poisoned
>                         machines where the WebClient service is running.
> ```
<!-- }}} -->

Usage

```sh
responder -I eth0 -w -d
```

___
<!-- }}} -->
