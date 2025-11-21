---
id: WAF
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/WAF
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# WAF

**Web Application Firewall** (*[WAF](https://en.wikipedia.org/wiki/Web_application_firewall)*)
is a specific form of application firewall that filters, monitors, and blocks
HTTP traffic to and from a web service.

By inspecting HTTP traffic, it can prevent attacks
exploiting a web application's known vulnerabilities,
(*e.g., SQL injection, cross-site scripting (XSS), file inclusion,
and improper system configuration*)

___

<!-- Identify {{{-->
## Identify

Identify if a Web Application Firewall
([WAF](https://en.wikipedia.org/wiki/Web_application_firewall))
is being used

### Nmap

[[Nmap]] — Identify WAF
(*[http-waf-detect](https://nmap.org/nsedoc/scripts/http-waf-detect.html) &
[http-waf-fingerprint](https://nmap.org/nsedoc/scripts/http-waf-fingerprint.html)*)

```sh
nmap -p <target_port> --script=http-waf-fingerprint,http-waf-detect <target>
```

### wafw00f

[[wafw00f]] — Identify WAF

```sh
wafw00f <target>
```

### WhatWaf

[[WhatWaf]] — Identify WAF

```sh
whatwaf -u <target>
```
___
<!-- }}} -->
