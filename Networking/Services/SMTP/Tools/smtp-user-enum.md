---
id: smtp-user-enum
aliases: []
tags: []
---

# smtp-user-enum

[smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum) —
Username guessing tool primarily for use against
the default Solaris SMTP service

<!-- Tip {{{-->
> [!tip]
>
> Can use either the following methods
>
> - [[SMTP/Usage#EXPN|EXPN]]
> - [[SMTP/Usage#RCPT TO|RCPT TO]]
> - [[SMTP/Usage#VRFY|VRFY]]
>
<!-- }}} -->

___

<!-- Installation {{{-->
## Installation

[Kali Tools](https://www.kali.org/tools/smtp-user-enum/)

```sh
sudo apt install smtp-user-enum
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Guess SMTP usernames

```sh
smtp-user-enum -M <method> -u <user> [-D <domain>] -t $target [-w 20]
```

[[Usage#VRFY|VRFY]] — Verify specific user

```sh
smtp-user-enum -M VRFY -u <user> -t $target -w 20 [-D <domain>]
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

[[Usage#VRFY|VRFY]] — Verify list of users

<!-- Warning {{{-->
> [!warning]
>
> Some servers may have higher timeout
>
<!-- }}} -->

```sh
smtp-user-enum -M VRFY -U <users.txt> -t $target -w 20
```

<!-- Info {{{-->
> [!info]-
>
> - `w`: Set timeout to `20` seconds (*defaults to* `10` *seconds*)
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```sh
> smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 10.129.33.217
> ```
<!-- }}} -->

[[Usage#RCPT TO|RCPT TO]] — Identify the recipient of an e-mail message

```sh
smtp-user-enum -M RCPT -u <user> -t $target -w 20 [-D <domain>]
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
> ```
> ```sh
> Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )
>
>  ----------------------------------------------------------
> |                   Scan Information                       |
>  ----------------------------------------------------------
>
> Mode ..................... RCPT
> Worker Processes ......... 5
> Usernames file ........... userlist.txt
> Target count ............. 1
> Username count ........... 78
> Target TCP port .......... 25
> Query timeout ............ 5 secs
> Target domain ............ inlanefreight.htb
>
> ######## Scan started at Thu Apr 21 06:53:07 2022 #########
> 10.129.203.7: jose@inlanefreight.htb exists
> 10.129.203.7: pedro@inlanefreight.htb exists
> 10.129.203.7: kate@inlanefreight.htb exists
> ######## Scan completed at Thu Apr 21 06:53:18 2022 #########
> 3 results.
>
> 78 queries in 11 seconds (7.1 queries / sec)
> ```
<!-- }}} -->

[[Usage#EXPN|EXPN]] — Identify the recipient of an e-mail message

```sh
smtp-user-enum -M EXPN -u <user> -t $target -w 20 [-D <domain>]
```

____
<!-- }}} -->
