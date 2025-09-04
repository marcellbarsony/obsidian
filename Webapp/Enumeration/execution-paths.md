# Execution paths

<!-- Burp Suite {{{-->
## Burp Suite

- Check **Site Map** for directories
- Check intercepted requests for
    - Cookies
    - Parameters

<!-- }}} -->

<!-- Dirsearch {{{-->
## Dirsearch

[dirsearch](https://github.com/maurosoria/dirsearch) web path scanner

```sh
dirsearch.py [-u|--url] {target} [-e|--extensions] {extensions} [options]
```
<!-- }}} -->

<!-- Gobuster {{{-->
## Gobuster

- [Gobuster - GitHub](https://github.com/OJ/gobuster)
- [Gobuster - Man (Debian)](https://manpages.debian.org/testing/gobuster/gobuster.1.en.html)
- [Gobuster - Man (Ubuntu)](https://manpages.ubuntu.com/manpages/focal/man1/gobuster.1.html)

### Usage

Modes

```sh
# Help
gobuster help

# Help <mode>
gobuster help <mode>

# Directory brute-forcing mode
gobuster dir <flags>

# DNS subdomain brute-forcing mode
gobuster dns <flags>

# S3 open bucket enumeration and look for existence and bucket
gobuster s3 <flags>

gobuster gcs <flags>
gobuster vhost <flags>
gobuster fuzz <flags>
gobuster tftp <flags>
```

Flags

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

Examples

```sh
# Directory brute-forcing
gobuster dir -u {target} -w /usr/share/wordlists/list.txt
```

<!-- }}} -->
