# Findomain

[Findomain](https://github.com/Findomain/Findomain)
uses Certificate Transparency logs and well-tested APIs to find subdomains

## Installation

Install on Debian-based distributions

```sh
sudo apt install findomain
```

Verify installation

```sh
findomain -h
```

## Usage

DNS Subdomain enumeration

```sh
findomain -t "<target_domain>" -a
```
