---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SMTP/Enumeration
links: "[[Networking/Services/SMTP/General|SMTP]]"
---

# Enumeration

- [Hacktricks - SMTP/s](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html)

<!-- Banner Grabbing {{{-->
## Banner Grabbing

<!-- SMTP {{{-->
### SMTP

#### Netcat

Get banner with [[netcat]]

```sh
nc -vn <target> 25
```

Get banner with [[netcat]] `EHLO`

```sh
echo "EHLO test" | nc <target> 25
```

#### Telnet

Get banner with [[Telnet/General|Telnet]]

```sh
telnet <target> 25
```

<!-- }}} -->

<!-- SMTPS {{{-->
### SMTPS

SSL/TLS with `starttls` command

```sh
openssl s_client -starttls smtp -crlf -connect smtp.mailgun.org:587
```

SSL/TLS without `starttls` command

```sh
openssl s_client -crlf -connect smtp.mailgun.org:465
```

<!-- }}} -->

___

<!-- }}} -->

<!-- Nmap {{{-->
## Nmap

Detect SMTP service

```sh
nmap -p 25,465,587 <target> -oA smtp-identify
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap -p 25,465,587 10.129.33.217 -oA smtp-identify
> ```
> ```sh
> Nmap scan report for 10.129.33.217
> Host is up (0.62s latency).
>
> PORT    STATE  SERVICE
> 25/tcp  open   smtp
> 465/tcp closed smtps
> 587/tcp closed submission
> ```
<!-- }}} -->

Discover SMTP services & server capabilities

```sh
sudo nmap -sC -sV -p 25 <target> -oA smtp-default-scripts
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap -sC -sV -p25 10.129.33.217 -oA smtp-default-scripts
> ```
> ```sh
> PORT   STATE SERVICE VERSION
> 25/tcp open  smtp
> |_smtp-commands: mail1, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
> | fingerprint-strings: 
> |   Hello: 
> |     220 InFreight ESMTP v2.11
> |_    Syntax: EHLO hostname
> ```
<!-- }}} -->

<!-- Scripts {{{-->
### Scripts

Discover SMTP commands
([smtp-commands](https://nmap.org/nsedoc/scripts/smtp-commands.html))

```sh
nmap -p 25 --script smtp-commands <target> -oA smtp-script-commands
```

Discover SMTP users
([smtp-enum-users](https://nmap.org/nsedoc/scripts/smtp-enum-users.html))

```sh
nmap -p 25 --script smtp-enum-users <target> -oA smtp-script-enum-users
```

Discover NTLM authentication details
([smtp-ntlm-info](https://nmap.org/nsedoc/scripts/smtp-ntlm-info.html))

```sh
nmap -p 25 --script smtp-ntlm-info <target> -oA smtp-script-ntlm-info
```

Run all SMTP-related scripts

```sh
nmap -p 25,465,587 --script smtp-* <target> -oA smtp--script-all
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nmap -p25 --script smtp-commands 10.129.33.217 -oA smtp-commands
> ```
> ```sh
> PORT   STATE SERVICE
> 25/tcp open  smtp
> |_smtp-commands: mail1, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
> ```
<!-- }}} -->

Check for [[Networking/Services/SMTP/Exploitation#Open Relay Attack|Open Realy Attack]]
([smtp-open-relay](https://nmap.org/nsedoc/scripts/smtp-open-relay.html))

```sh
nmap -p25 --script smtp-open-relay <target> -v -oA smtp-script-open-relay
```

<!-- }}} -->

<!-- CVE Scripts {{{-->
### CVE Scripts

[[Networking/Services/SMTP/Exploitation#CVE-2010-4344|CVE-2010-4344]] (
[smtp-vuln-cve2010-4344](https://nmap.org/nsedoc/scripts/smtp-vuln-cve2010-4344.html)
)

```sh
sudo nmap -sV --script=smtp-vuln-cve2010-4344 -p 25,465,587 <target> -oA smtp-vuln-cve2010-4344
```

[[Networking/Services/SMTP/Exploitation#CVE-2011-1720|CVE-2011-1720]] (
[smtp-vuln-cve2011-1720](https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1720.html)
)

```sh
sudo nmap -sV --script=smtp-vuln-cve2011-1720 -p 25,465,587 <target> -oA smtp-vuln-cve2011-1720
```

[[Networking/Services/SMTP/Exploitation#CVE-2011-1764|CVE-2011-1764]] (
[smtp-vuln-cve2010-1764](https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1764.html)
)

```sh
sudo nmap -sV --script=smtp-vuln-cve2011-1764 -p 25,465,587 <target> -oA smtp-vuln-cve2011-1764
```

<!-- }}} -->

___

<!-- }}} -->

<!-- User {{{-->
## User

<!-- smtp-user-enum {{{-->
### smtp-user-enum

Verify specific user

```sh
smtp-user-enum -M VRFY -u <user> -t <target> -w 20
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> smtp-user-enum -M VRFY -u root -t 10.129.33.217
> ```
> ```sh
>  ----------------------------------------------------------
> |                   Scan Information                       |
>  ----------------------------------------------------------
>
> Mode ..................... VRFY
> Worker Processes ......... 5
> Target count ............. 1
> Username count ........... 1
> Target TCP port .......... 25
> Query timeout ............ 5 secs
> Target domain ............ 
> ```
<!-- }}} -->

Verify user list

```sh
smtp-user-enum -M VRFY -U <users.txt> -t <target> -w 20
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 10.129.33.217
> ```
<!-- }}} -->

<!-- Warning {{{-->
> [!warning]
>
> Some servers may have higher timeout
>
> > [!tip]-
> >
> > Set timeout to `20` seconds (*defaults to* `10` *seconds*)
> >
> > ```sh
> > smtp-user-enum -M VRFY -U users.txt -t 10.129.33.217 -w 20
> > ```
<!-- }}} -->

<!-- }}} -->

<!-- Metasploit {{{-->
### Metasploit

The [smtp_enum](https://www.rapid7.com/db/modules/auxiliary/scanner/smtp/smtp_enum/)
scanner can reveal a list of valid users

```sh
use auxiliary/scanner/smtp/smtp_enum
```

<!-- Example {{{-->
> [!example]-
>
>
> 1. [[Metasploit#Launch Metasploit|Launch Metasploit]]
>
> 2. [[Metasploit#Search Exploit|Search Scanner]]
>
> ```sh
> search smtp
> ```
>
> 3. [[Metasploit#Select Exploit|Select Scanner]]
>
> ```sh
> use auxiliary/scanner/smtp/smtp_enum
> ```
>
> 4. [[Metasploit#Show Actions|Show Actions]]
>
> 5. [[Metasploit#Set Actions|Set Actions]]
>
> 6. [[Metasploit#Show Options|Show Options]]
>
> 7. [[Metasploit#Set Options|Set Options]]
>
> 8. [[Metasploit#Check Exploit|Check Scanner]]
>
> 9. [[Metasploit#Run Exploit|Run]]
<!-- }}} -->

<!-- }}} -->

___

<!-- }}} -->
