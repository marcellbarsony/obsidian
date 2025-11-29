---
id: Burp Suite
aliases: []
tags:
  - Webapp/Tools/Burp-Suite/Burp-Suite
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

# Burp Suite

___

<!-- Enumeration {{{-->
## Enumeration

- Check [Site Map](https://portswigger.net/burp/documentation/desktop/tools/target/site-map)
  for directories
- Check intercepted requests for
    - Cookies
    - Parameters

___
<!-- }}} -->

<!-- Proxy {{{-->
## Proxy

<!-- Automatic Modification {{{-->
### Automatic Modification

<!-- Request {{{-->
#### Request

Automatic Request Modification

```sh
Proxy > Match and replace
```
```sh
Proxy > Proxy settings > Tools > Proxy > HTTP match and replace rules
```

<!-- Example {{{-->
> [!example]-
>
> ![[match-replace-rule.png]]
<!-- }}} -->

<!-- }}} -->

<!-- Response {{{-->
#### Response

Automatic Response Modification

```sh
Proxy > Proxy settings > Tools > Proxy > HTTP match and replace rules
```

<!-- Example {{{-->
> [!example]-
>
> ![[match-replace-response.png]]
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Intruder {{{-->
## Intruder


___
<!-- }}} -->

<!-- Scanner {{{-->
## Scanner


___
<!-- }}} -->
