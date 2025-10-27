---
id: Gobuster
aliases: []
tags:
  - Webapp/Enumeration/Tools/Gobuster
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Gobuster

[Gobuster](https://github.com/OJ/gobuster)
is a directory/file, DNS and virtual host brute-forcing tool

- [Gobuster - Man (Debian)](https://manpages.debian.org/testing/gobuster/gobuster.1.en.html)
- [Gobuster - Man (Ubuntu)](https://manpages.ubuntu.com/manpages/focal/man1/gobuster.1.html)

___

## Usage

<!-- Examples {{{-->
### Help

Help

```sh
gobuster help
```

Help `<mode>`

```sh
gobuster help <mode>
```

### Directory Enumeration

Directory enumeration

```sh
gobuster dir <flags> -u <target>
```

> [!example]-
>
> ```sh
> gobuster dir -u 10.10.10.10:1000 -w /usr/share/seclists/Discovery/Web-Content/common.txt
> ```

### Recursive Directory Enumeration

```sh
gobuster dir -u http://<host>/content/private/plugins/ -w <wordlist.txt>
```

### DNS Subdomain Enumeration

Brute Force DNS subdomain enumeration

```sh
gobuster dns <flags> -d <target> -w <wordlist.txt>
```

> [!example]-
>
> ```sh
> gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
> ```

### Brute Forcing

Virtual Host brute-forcing

```sh
gobuster vhost <flags>
```

General purpose fuzzing

```sh
gobuster fuzz <flags>
```

TFTP file path brute-forcing

```sh
gobuster tftp <flags>
```

### Cloud

Amazon Web Services (AWS) S3 bucket enumeration

```sh
gobuster s3 <flags>
```

Google Cloud Storage (GCS) bucket enumeration

```sh
gobuster gcs <flags>
```
___
<!-- }}} -->

<!-- Options {{{-->
### Options

> [!example]-
>
> Ignore redirect (301) responses
>
> ```sh
> -b
> ```
>
> Don't display progress
>
> ```sh
> -z, --no-progress
> ```
>
> Output file to write results to (defaults to stdout)
>
> ```sh
> -o, --output string
> ```
>
> File containing replacement patterns
>
> ```sh
> -p, --pattern string
> ```
>
> Don't print the banner and other noise
>
> ```sh
> -q, --quiet
> ```
>
> Number of concurrent threads (default 10)
>
> ```sh
> -t, --threads int
> ```
>
> Verbose output (errors)
>
> ```sh
> -v, --verbose
> ```
>
> Path to the wordlist
>
> ```sh
> -w, --wordlist string
> ```

___
<!-- }}} -->
