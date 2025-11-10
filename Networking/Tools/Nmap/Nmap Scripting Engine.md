---
id: Nmap Scripting Engine
aliases: ["NSE"]
tags:
  - Networking/Tools/Nmap/Nmap-Scripting-Engine
---

# Nmap Scripting Engine (NSE)

The **Nmap Scripting Engine** (**NSE**) provides the possibility
to create scripts in Lua for interaction with certain devices

___

<!-- Update Script Database {{{-->
## Update Script Database

Update the Nmap Scripting Engine database

```sh
sudo nmap --script-updatedb
```
___
<!-- }}} -->

<!-- Aggressive Scan {{{-->
## Aggressive Scan

Run an aggressive scan

```sh
sudo nmap <target_ip> -p 80 -A -oA aggressive-scan
```

> [!info]-
>
> - `-A`: Service detection, OS detection,
>   traceroute and uses defaults scripts
___
<!-- }}} -->

<!-- Default Scripts {{{-->
## Default Scripts

Run default scripts

```sh
sudo nmap -sC <target_ip> -oA scripts-default
```
___
<!-- }}} -->

<!-- Defined Scripts {{{-->
## Defined Scripts

Run a defined script

```sh
sudo nmap <target_ip> --script <script-name>,<script-name>,...
```
___
<!-- }}} -->

<!-- Specific Scripts Category {{{-->
## Specific Scripts Category

Run a specific script category

<!-- Example {{{-->
> [!info]- Script Categories
>
> There are a total of 14 categories into which these scripts can be divided
>
> | Category | Description |
> | --- | --- |
> | auth      | Determination of authentication credentials |
> | broadcast | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans |
> | brute     | Executes scripts that try to log in to the respective service by brute-forcing with credentials |
> | default   | Default scripts executed by using the -sC option |
> | discovery | Evaluation of accessible services |
> | dos       | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services |
> | exploit   | This category of scripts tries to exploit known vulnerabilities for the scanned port |
> | external  | Scripts that use external services for further processing |
> | fuzzer    | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time |
> | intrusive | Intrusive scripts that could negatively affect the target system |
> | malware   | Checks if some malware infects the target system |
> | safe      | Defensive scripts that do not perform intrusive and destructive access |
> | version   | Extension for service detection |
> | vuln      | Identification of specific vulnerabilities |
<!-- }}} -->

```sh
sudo nmap <target_ip> --script <category> -oA script-<category>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
> ```
<!-- }}} -->
___
<!-- }}} -->

<!-- Vulnerability Assessment {{{-->
## Vulnerability Assessment

Run a vulnerability assessment script

```sh
sudo nmap -sV <target_ip> -p 80 --script vuln -oA script-vulnerability-assessment
```

> [!info]-
>
> - `--script vuln`: Uses all related scripts from specified category
___
<!-- }}} -->
