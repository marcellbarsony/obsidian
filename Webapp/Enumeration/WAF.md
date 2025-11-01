---
id: WAF
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/WAF
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# WAF

## Identify

Identify if a Web Application Firewall
([WAF](https://en.wikipedia.org/wiki/Web_application_firewall))
is being used

### wafw00f

[[wafw00f]] — Identify WAF

```sh
wafw00f <target>
```

### Nmap

[[Nmap]]
([http-waf-detect](https://nmap.org/nsedoc/scripts/http-waf-detect.html))
([http-waf-fingerprint](https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html))
— Identify WAF

```sh
nmap -p <target_port> --script=http-waf-fingerprint,http-waf-detect <target>
```

### WhatWaf

[WhatWaf](https://github.com/Ekultek/WhatWaf)
— Identify WAF

```sh
whatwaf -u <target>
```
