---
id: Enumeration
aliases: []
tags:
  - Networking/Services/MongoDB/Enumeration
---

# Enumeration

___

<!-- Service {{{-->
## Service

[[Nmap]] — Service detection

```sh
nmap $target -p 27017,27018 -oA mongodb-service-detection
```

[[Nmap]] — Server information

```sh
nmap $target -p 27017 --script mongodb-info -oA mongodb-script-mongodb-info
```

[[Nmap]] — List databases

```sh
nmap $target -p 27017 --script mongodb-databases -oA mongodb-script-mongodb-databases
```

___

<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

[[Netcat]] — Banner grabbing

```sh
nc -vn $target 27017
```
___
<!-- }}} -->

<!-- Metasploit {{{-->
## Metasploit


```sh
use auxiliary/scanner/mongodb/mongodb_info
```

```sh
use auxiliary/scanner/mongodb/mongodb_enum
```

<!-- Example {{{-->
> [!example]-
>
> Query the MSSQL instance for a specific user/pass
> (*default is sa with blank*)
>
> ```sh
> msf > use auxiliary/scanner/mssql/mssql_login
> msf auxiliary(mssql_login) > show actions
>     ...actions...
> msf auxiliary(mssql_login) > set ACTION < action-name >
> msf auxiliary(mssql_login) > show options
>     ...show and set options...
> msf auxiliary(mssql_login) > run
> ```
<!-- }}} -->

___
<!-- }}} -->
