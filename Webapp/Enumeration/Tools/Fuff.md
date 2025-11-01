---
id: Fuff
aliases: []
tags:
  - Webapp/Enumeration/Tools/Fuff
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Fuff

- [fuff - Github](https://github.com/ffuf/ffuf)

<!-- Installation {{{-->
## Installation

Install on Debian-based distributions

```sh
sudo apt-get install ffuf
```
___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

### Vhost Brute Force

[[Virtual Hosts#Brute Force|Virtual Host Brute Force]]

```sh
ffuf -H "Host: FUZZ.<domain>" -H "User-Agent: PENTEST" -c -w "<wordlist.txt>" -u <target>
```

```sh
ffuf -c -r -w "<wordlist.txt>" -u "http://FUZZ.<target>/"
```

Filter results by response sizes (*e.g., `-fs 109, 208`*)

```sh
fuf -w namelist.txt -u http://10.129.184.109 -H "HOST: FUZZ.inlanefreight.htb" -fs 10918
```
___
<!-- }}} -->
