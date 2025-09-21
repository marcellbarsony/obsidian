---
id: Nmap Scripting Engine
aliases: ["NSE"]
tags:
  - Networking/Tools/Nmap/Nmap-Scripting-Engine
---

# Nmap Scripting Engine (NSE)

## Default Scripts

```sh
sudo nmap <target_ip> -sC
```

## Specific Scripts Category

```sh
sudo nmap <target_ip> --script <category>
```

```sh
sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
```

## Defined Scripts

```sh
sudo nmap <target_ip> --script <script-name>,<script-name>,...
```

## Agressive Scan

```sh
sudo nmap <target_ip> -p 80 -A
```

- `-A`: Service detection, OS detection, traceroute and uses defaults scripts

## Vulnerability Assesment

```sh
sudo nmap <target_ip> -p 80 -sV --script vuln
```

- `--script vuln`: Uses all related scripts from specified category
