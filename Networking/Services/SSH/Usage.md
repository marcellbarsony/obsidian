---
id: Usage
aliases:
  - Secure Shell
tags:
  - Networking/Services/SSH/Usage
links: "[[SSH]]"
---

# Usage

Connect to a host

```sh
# Synopsis
ssh {username}@{target_ip}

# Specify private key
ssh {username}@{target_ip} -i {private_key}

# Specify target port
ssh {username}@{target_ip} -p {target_port}

# Example
ssh bob@10.10.10.10 -i id_rsa -p 12345
```
