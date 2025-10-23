---
id: Enumeration
aliases: []
tags:
  - Networking/Services/WinRM/Enumeration
---

# Enumeration

<!-- Service {{{-->
## Service

Detect WinRM services and identify server capabilities

```sh
nmap -p 5985,5986 <target> -oA winrm-service
```

Detect WinRM version

```sh
nmap -p 5985,5986 -sV <target> -oA winrm-service-version
```

Enumerate HTTP headers ([http-headers](https://nmap.org/nsedoc/scripts/http-methods.html))

```sh
nmap -p 5985 --script http-methods <target> -oA winrm-script-http-methods
```

Enumerate HTTP methods ([http-methods](https://nmap.org/nsedoc/scripts/http-methods.html))

```sh
nmap -p 5985 --script http-headers <target> -oA winrm-script-http-headers
```

Check WinRM configuration

```sh
nmap -p 5985,5986 --script http-wsman-info <target> -oA winrm-script-hhtp-wsman-info
```

___

<!-- }}} -->

<!-- Banner Grabbing {{{-->
## Banner Grabbing

Gather version and service information

Using [[netcat]]

```sh
nc -vn <target> 5985
```

Using curl

```sh
curl http://<target>:5985/wsman
```

Check WinRM configuration

> [!example]-
>
> ```sh
> curl -H "Content-Type: application/soap+xml;charset=UTF-8" \
>   http://target.com:5985/wsman \
>   -d '<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>'
> ```

___
<!-- }}} -->
