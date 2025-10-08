---
id: Usage
aliases:
  - Secure Shell
tags:
  - Networking/Services/SSH/Usage
links: "[[SSH]]"
---

# Usage

## Connect

Connect to a host

```sh
ssh {username}@{target_ip}
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ssh bob@10.10.10.10 -i id_rsa -p 1234
> ```
>
> - `-i id_rsa`: Specify private key (*optional*)
> - `-p 1234`: Specify target port (*optional*)
<!-- }}} -->
