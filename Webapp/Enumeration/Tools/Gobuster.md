---
id: Gobuster
aliases: []
tags:
  - Webapp/Enumeration/Tools/Gobuster
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Gobuster

GoBuster is a directory/file, DNS and virtual host brute-forcing tool

- [Gobuster - GitHub](https://github.com/OJ/gobuster)
- [Gobuster - Man (Debian)](https://manpages.debian.org/testing/gobuster/gobuster.1.en.html)
- [Gobuster - Man (Ubuntu)](https://manpages.ubuntu.com/manpages/focal/man1/gobuster.1.html)

## Usage

### Modes

```sh
# Help
gobuster help

# Help <mode>
gobuster help <mode>

# Directory enumeration
gobuster dir <flags>

# DNS subdomain enumeration
gobuster dns <flags>

# Amazon Web Services (AWS) S3 bucket enumeration
gobuster s3 <flags>

# Google Cloud Storage (GCS) bucket enumeration
gobuster gcs <flags>

# Virtual Host brute-forcing
gobuster vhost <flags>

# General purpose fuzzing
gobuster fuzz <flags>

# TFTP file path brute-forcing
gobuster tftp <flags>
```

### Examples

```sh
# Directory enumeration
gobuster dir -u 10.10.10.10:1000 -w /usr/share/seclists/Discovery/Web-Content/common.txt

# DNS subdomain enumeration
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```

### Options

```sh
# Don't display progress
-z, --no-progress

# Output file to write results to (defaults to stdout)
-o, --output string

# File containing replacement patterns
-p, --pattern string

# Don't print the banner and other noise
-q, --quiet

# Number of concurrent threads (default 10)
-t, --threads int

# Verbose output (errors)
-v, --verbose

# Path to the wordlist
-w, --wordlist string
```
