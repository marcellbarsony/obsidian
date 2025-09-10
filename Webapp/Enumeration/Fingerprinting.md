---
id: Fingerprinting
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Fingerprinting

Fingerpring the web server for version, application framework, authentication
options, and missing security options.

## Type & Web server version

### Banner grabbing

<!-- cURL {{{-->
#### cURL

Synopsis

```sh
curl -I http://{target_url}
```

Example

```sh
# Banner grabbing & Web server headers
curl -IL http://example.com

# Spoof user agent and follow redirects
curl -A "Custom user-agent" -L {target_ip}
```
<!-- }}} -->

#### Whatweb

Extract the version of the web server, supporting frameworks, and applications.

```sh
whatweb {target_ip}

whatweb --no-errors 10.10.10.0/24
```

<!-- Netcat {{{-->
#### Netcat

```sh
nc {target_url} 80
```
```sh
nc example.com 80
```

Then type

```sh
HEAD / HTTP/1.0
Host: {target_url}
```
<!-- }}} -->

<!-- Nmap {{{-->
### Nmap scan

```sh
nmap -sV [--version-all] {target_url}
```
```sh
nmap -sV --version-all example.com
```
<!-- }}} -->

<!-- Error page {{{-->
### Error page

```sh
curl -X GET http://example.com/404page
```
<!-- }}} -->

<!-- Nikto vulnerability scanner {{{-->
### Nikto vulnerability scanner
```sh
nikto -h http://{target_url}
```
```sh
nikto -h http://example.com
```
<!-- }}} -->

## Version details & CVEs

- Search for additional version information
- Search the web for well-known vulnerabilities and exploits
