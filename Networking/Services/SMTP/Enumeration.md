---
id: Enumeration
aliases: []
tags:
  - Networking/Services/SMTP/Enumeration
links: "[[Networking/Services/SMTP/General|SMTP]]"
---

# Enumeration

<!-- Resources {{{-->
> [!info]- Resources
>
> - [HackTricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html)
> - [Hackviser](https://hackviser.com/tactics/pentesting/services/smtp#enumeration)
>
<!-- }}} -->

___

<!-- Server {{{-->
## Server

Identify an organization's mail server

1. Query [[DNS/General#MX|MX]] records

[[dig]]

```sh
dig <target_domain> mx | grep "MX" | grep -v ";"
```

```sh
dig [@<dns_ip>] <target_domain> mx | grep "MX" | grep -v ";"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> dig microsoft.com mx | grep "MX" | grep -v ";"
> ```
> ```sh
> microsoft.com.          3301    IN      MX      10 microsoft-com.mail.protection.outlook.com.
> ```
<!-- }}} -->

[[host]]

```sh
host -t MX <target_domain>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> host -t MX microsoft.com
> ```
<!-- }}} -->

2. Query the found e-mail servers for their [[DNS/General#A|A]] records

[[dig]]

```sh
dig [@<dns_ip>] <smtp_server_ip> a
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> dig microsoft-com.mail.protection.outlook.com a
> ```
> ```sh
> ;; ANSWER SECTION:
> microsoft-com.mail.protection.outlook.com. 2400 IN A 52.101.9.26
> microsoft-com.mail.protection.outlook.com. 2400 IN A 52.101.11.3
> microsoft-com.mail.protection.outlook.com. 2400 IN A 52.101.41.26
> microsoft-com.mail.protection.outlook.com. 2400 IN A 52.101.10.8
> ```
<!-- }}} -->

[[host]]

```sh
host -t A <smtp_server_ip>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> host -t A mail1.inlanefreight.htb.
> ```
> ```sh
> mail1.inlanefreight.htb has address 10.129.14.128
> ```
>
<!-- }}} -->

___
<!-- }}} -->

<!-- Service {{{-->
## Service

Enumerate SMTP/S service

<!-- Info {{{-->
> [!info]- Ports
>
> [[SMTP/General#Ports|SMTP]]
>
> | Port      | Service                 |
> | --------- | ----------------------- |
> | `TCP/25`  | SMTP Unencrypted        |
> | `TCP/465` | SMTP Encrypted          |
> | `TCP/587` | SMTP Encrypted/STARTTLS |
>
> [[IMAP-POP3/General#IMAP|IMAP]]
>
> | Port      | Service                 |
> | --------- | ----------------------- |
> | `TCP/143` | IMAP4 Unencrypted       |
> | `TCP/993` | IMAP4 Encrypted         |
>
> [[IMAP-POP3/General#POP3|POP3]]
>
> | Port      | Service                 |
> | --------- | ----------------------- |
> | `TCP/110` | POP3 Unencrypted        |
> | `TCP/995` | POP3 Encrypted          |
>
<!-- }}} -->

[[Nmap]] — Detect SMTP service

```sh
nmap $target -p 25,465,587 -oA smtp-identify
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

[[Nmap]] — Enumerate SMTP services & server capabilities

```sh
sudo nmap -sC -sV $target -p 25 -oA smtp-default-scripts
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

[[Nmap]] — Enumerate all SMTP ports

```sh
sudo nmap -sC -sV -Pn $target -p 25,110,143,465,587,993,995 -oA smtp-all-ports
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128
> ```
>
> ```sh
> Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-27 17:56 CEST
> Nmap scan report for 10.129.14.128
> Host is up (0.00025s latency).
>
> PORT   STATE SERVICE VERSION
> 25/tcp open  smtp    Postfix smtpd
> |_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
> MAC Address: 00:00:00:00:00:00 (VMware)
> ```
<!-- }}} -->

<!-- Banner {{{-->
### Banner

Grab SMTP/S service banner

**SMTP**

[[Netcat]]

```sh
nc -vn $target 25
```

```sh
echo "EHLO test" | nc $target 25
```

[[Telnet/General|Telnet]]

```sh
telnet $target 25
```

**SMTPS**

[openssl s_client](https://docs.openssl.org/1.0.2/man1/s_client/) —
SSL/TLS without `STARTTLS` command

```sh
openssl s_client -crlf -connect $target:465
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> openssl s_client -crlf -connect smtp.mailgun.org:465
> ```
<!-- }}} -->

[openssl s_client](https://docs.openssl.org/1.0.2/man1/s_client/) —
[Opportunistic TLS](https://en.wikipedia.org/wiki/Opportunistic_TLS)
with `STARTTLS` command

```sh
openssl s_client -starttls smtp -crlf -connect $target:587
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> openssl s_client -starttls smtp -crlf -connect inlanefreight.htb:587
> ```
> ```sh
> Connecting to 10.129.4.29
> CONNECTED(00000003)
> Didn't find STARTTLS in server response, trying anyway...
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- Scripts {{{-->
### Scripts

[[Nmap]] — Discover SMTP commands
(*[smtp-commands](https://nmap.org/nsedoc/scripts/smtp-commands.html)*)

```sh
nmap $target -p 25 --script smtp-commands -oA smtp-script-commands
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

[[Nmap]] — Discover SMTP users
(*[smtp-enum-users](https://nmap.org/nsedoc/scripts/smtp-enum-users.html)*)

```sh
nmap $target -p 25 --script smtp-enum-users -oA smtp-script-enum-users
```

[[Nmap]] — Run all SMTP-related scripts

```sh
nmap $target -p 25,465,587 --script smtp-* -oA smtp--script-all
```

[[Nmap]] — Enumerate [[NTLM]] authentication details (*Windows*)
(*[smtp-ntlm-info](https://nmap.org/nsedoc/scripts/smtp-ntlm-info.html)*)

```sh
nmap $target -p 25 --script smtp-ntlm-info -oA smtp-script-ntlm-info
```

<!-- Tip {{{-->
> [!tip]- Manual Testing
>
> Obtain version information
>
> ```sh
> root@kali: telnet example.com 587
> ```
> ```sh
> 220 example.com SMTP Server Banner
> ```
> ```sh
> >> HELO
> ```
> ```sh
> 250 example.com Hello [x.x.x.x]
> ```
> ```sh
> >> AUTH NTLM 334
> ```
> ```sh
> NTLM supported
> ```
> ```sh
> >> TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=
> 334 TlRMTVNTUAACAAAACgAKADgAAAAFgooCBqqVKFrKPCMAAAAAAAAAAEgASABCAAAABgOAJQAAAA9JAEkAUwAwADEAAgAKAEkASQBTADAAMQABAAoASQBJAFMAMAAxAAQACgBJAEkAUwAwADEAAwAKAEkASQBTADAAMQAHAAgAHwMI0VPy1QEAAAAA
> ```
<!-- }}} -->


<!-- }}} -->

___
<!-- }}} -->

<!-- CVE Scripts {{{-->
## CVE Scripts

[[SMTP/Exploitation#CVE-2010-4344|CVE-2010-4344]]
(*[smtp-vuln-cve2010-4344](https://nmap.org/nsedoc/scripts/smtp-vuln-cve2010-4344.html)*)

```sh
sudo nmap -sV $target -p 25,465,587 -sV --script=smtp-vuln-cve2010-4344 -oA smtp-vuln-cve2010-4344
```

[[SMTP/Exploitation#CVE-2011-1720|CVE-2011-1720]]
(*[smtp-vuln-cve2011-1720](https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1720.html)*)

```sh
sudo nmap -sV $target -p 25,465,587 --script=smtp-vuln-cve2011-1720 -oA smtp-vuln-cve2011-1720
```

[[SMTP/Exploitation#CVE-2011-1764|CVE-2011-1764]]
(*[smtp-vuln-cve2010-1764](https://nmap.org/nsedoc/scripts/smtp-vuln-cve2011-1764.html)*)

```sh
sudo nmap -sV $target -p 25,465,587 --script=smtp-vuln-cve2011-1764 -oA smtp-vuln-cve2011-1764
```

___
<!-- }}} -->

<!-- Open Relay {{{-->
## Open Relay

Enumerate [[Networking/Services/SMTP/Exploitation#Open Relay Attack|Open Relay Attack]]

[[Nmap]] — Enumerate Open Relay
(*[smtp-open-relay](https://nmap.org/nsedoc/scripts/smtp-open-relay.html)*)

```sh
nmap $target -p25 --script smtp-open-relay -oA smtp-script-open-relay -v
```

Manual testing (*external to external*)

```sh
telnet $target 25
```
```sh
MAIL FROM:<external1@example.com>
RCPT TO:<external2@anotherdomain.com>
DATA
Test
.
```

[[swaks]] — Enumerate Open Relay

```sh
swaks --server $target \
  --to <external@domain.com> \
  --from <external@otherdomain.com>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> swaks --server $target \
>   --to <external@domain.com> \
>   --from <external@otherdomain.com>
> ```
<!-- }}} -->

___
<!-- }}} -->
