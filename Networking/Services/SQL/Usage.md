---
id: Usage
aliases: []
tags:
  - Networking/Services/SQL/Usag
links: "[[SQL]]"
---

# Usage

## mssqlclient.py

[mssqlclient.py](https://github.com/fortra/impacket/blob/ff8c200fd040b04d3b5ff05449646737f836235d/examples/mssqlclient.py#L4)
is a script from the [Impacket collection](https://github.com/fortra/impacket)

Connect to a MSSQL server

```sh
mssqlclient.py {TARGET_HOST/USER|TARGET_IP/USER}@{TARGET_IP} -windows_auth
```
