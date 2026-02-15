---
id: Enumeration
aliases: []
tags:
  - Networking/Services/Apache-HTTP-Server/Enumeration
---

# Enumeration

[Apache HTTP Server](https://httpd.apache.org/) (*httpd*)
Enumeration

___

<!-- Shellshock {{{-->
## Shellshock

[[Shellshock#Enumeration|Enumerate Shellshock]] for Apache HTTPD

[mod_cgi](https://httpd.apache.org/docs/current/mod/mod_cgi.html)
is used run CGI scripts on the server

```sh
http://$target/mod-cgi/
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> http://$target/mod-cgi/script.sh
> ```
>
<!-- }}} -->

[[Ffuf]] - [[Execution Paths#Extensions|Enumerate extensions]]
for shell scripts

```sh
ffuf -w <wordlist> -u http://$target/mod-cgi/FUZZ -ext .sh,.txt
```

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
> -u http://$target/mod-cgi/FUZZ \
> -e .sh,.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ \
> -u http://$target/mod-cgi/FUZZ \
> -e .sh,.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt:FUZZ \
> -u http://$target/mod-cgi/FUZZ \
> -e .sh,.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ \
> -u http://$target/mod-cgi/FUZZ \
> -e .sh,.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ \
> -u http://$target/mod-cgi/FUZZ \
> -e .sh,.txt \
> -ic
> ```
<!-- }}} -->

[[Pentest/Tools/Metasploit/Metasploit]] - [Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner](https://www.rapid7.com/db/modules/auxiliary/scanner/http/apache_mod_cgi_bash_env/)

```sh
use auxiliary/scanner/http/apache_mod_cgi_bash_env
```

<!-- Info {{{-->
> [!info]-
>
> This module scans for the [[Shellshock]] vulnerability,
> a flaw in how the Bash shell handles external environment variables.
> This module targets CGI scripts in the Apache web server
> by setting the `HTTP_USER_AGENT` environment variable to a
> malicious function definition.
>
> <!-- Tip {{{-->
> > [!tip]-
> >
> > Use `exploit/multi/handler` with a [[Pentest/Tools/Metasploit/Metasploit#Payloads|Payload]]
> > appropriate to your CMD,
> > set `ExitOnSession` to `false`, run -j,
> > and then run this module to create sessions on vulnerable hosts
> >
> <!-- }}} -->
>
> <!-- Note {{{-->
> > [!note]-
> >
> > Note that this is not the recommended method for obtaining shells.
> >
> > If you require sessions, please use the [apache_mod_cgi_bash_env_exec](https://www.rapid7.com/db/modules/exploit/multi/http/apache_mod_cgi_bash_env_exec/)
> > exploit module instead.
> <!-- }}} -->
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> 1. Show missing options
>
> ```sh
> show missing
> ```
> ```sh
>    Name       Current Setting  Required  Description
>    ----       ---------------  --------  -----------
>    RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
>    TARGETURI                   yes       Path to CGI script
> ```
>
> 2. Set local host
>
> ```sh
> set LHOST tun0
> ```
>
> 3. Set target host
>
> ```sh
> set RHOSTS $target
> ```
>
> 4. Set path to CGI script
>
> ```sh
> set TARGETURI /cgi-bin/script.sh
> ```
>
> 5. Run the scanner
>
> ```sh
> run
> ```
>
<!-- }}} -->

___
<!-- }}} -->
