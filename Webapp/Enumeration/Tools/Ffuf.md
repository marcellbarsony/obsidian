---
id: Fuff
aliases: []
tags:
  - Webapp/Enumeration/Tools/Ffuf
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Ffuf

[ffuf](https://github.com/ffuf/ffuf) (*Fuzz Faster U Fool*)
— Fast web fuzzer written in Go

___

<!-- Installation {{{-->
## Installation

[Kali Tools](https://www.kali.org/tools/ffuf/)

```sh
sudo apt install ffuf
```
___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

<!-- Web Fuzzing {{{-->
### Web Fuzzing

<!-- Directory Fuzzing {{{-->
#### Directory Fuzzing

Fuzz website directories

```sh
ffuf -w <wordlist>:FUZZ -u http://<target_ip>:<target_port>/FUZZ [-ic]
```

<!-- Info {{{-->
> [!info]-
>
> Assign the `FUZZ` keyword to the wordlist
> and place the `FUZZ` keyword where the directory would be within the URL
>
> - `-ic`: Ignore wordlist comments (default: `False`)
<!-- }}} -->

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> [[Dirbuster]]
>
> ```sh
> /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
> ```
> ```sh
> /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
> ```
>
> [[SecLists]]
>
> ```sh
> /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
> ```
>
> ```sh
> /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
> ```
>
> ```sh
> /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Page Fuzzing {{{-->
#### Page Fuzzing

Fuzz website pages

```sh
ffuf -w <wordlist>:FUZZ -u http://<target_ip>:<port>/blog/FUZZ[.ext] [-ic]
```

<!-- Info {{{-->
> [!info]-
>
> Assign the `FUZZ` keyword to the wordlist
> and place the `FUZZ` keyword where the directory would be within the URL
>
> - `-ic`: Ignore wordlist comments (default: `False`)
<!-- }}} -->

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> [[Dirbuster]]
>
> ```sh
> /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
> ```
> ```sh
> /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
> ```
>
> [[SecLists]]
>
> ```sh
> /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
> ```
>
> ```sh
> /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
> ```
>
> ```sh
> /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Extension Fuzzing {{{-->
#### Extension Fuzzing

Fuzz website page extensions

```sh
ffuf -w <wordlist>:FUZZ -u http://<target_ip>:<port>/blog/indexFUZZ [-ic]
```

<!-- Info {{{-->
> [!info]-
>
> Most websites has `index.*`
>
> The wordlist already contains a dot (`.`)
>
> - `-ic`: Ignore wordlist comments (default: `False`)
<!-- }}} -->

<!-- Wordlist {{{-->
> [!tip]- Wordlist
>
> [[SecLists]]
>
> ```sh
> /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt
> ```
> ```sh
> /usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions-big.txt
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Recursive Fuzzing {{{-->
#### Recursive Fuzzing

Fuzz websites recursively

```sh
ffuf -w <wordlist>:FUZZ -u http://<target_ip>:<port>/FUZZ -recursion [-recursion-depth 1] [-e .php] [-ic] -v
```

<!-- Info {{{-->
> [!info]-
>
> - `-recursion`: Recursive fuzzing
> - `-recursion-depth`: Recursion depth
> - `-e`: Specify extension
> - `-ic`: Ignore wordlist comments (default: `False`)
> - `-v`: Show full URLs
<!-- }}} -->


<!-- }}} -->

<!-- }}} -->

<!-- Domain Fuzzing {{{-->
### Domain Fuzzing

#### Subdomain Fuzzing

```sh
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
```

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> ```sh
> /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
> ```
<!-- }}} -->


<!-- }}} -->

___
<!-- }}} -->
