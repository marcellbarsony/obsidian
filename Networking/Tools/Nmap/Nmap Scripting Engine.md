---
id: Nmap Scripting Engine
aliases: ["NSE"]
tags:
  - Networking/Tools/Nmap/Nmap-Scripting-Engine
---

# Nmap Scripting Engine (NSE)

## Update Script Database

Update the Nmap Scripting Engine database

```sh
sudo nmap --script-updatedb
```

## Default Scripts

Run nmap default scripts

```sh
sudo nmap <target_ip> -sC
```

## Specific Scripts Category

Run a specific script category

```sh
sudo nmap <target_ip> --script <category>
```

```sh
sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
```

## Defined Scripts

Run a defined script

```sh
sudo nmap <target_ip> --script <script-name>,<script-name>,...
```

## Agressive Scan

Run an agressive scan

```sh
sudo nmap <target_ip> -p 80 -A
```

- `-A`: Service detection, OS detection, traceroute and uses defaults scripts

## Vulnerability Assesment

Run a vulnerability assesment script

```sh
sudo nmap <target_ip> -p 80 -sV --script vuln
```

- `--script vuln`: Uses all related scripts from specified category
