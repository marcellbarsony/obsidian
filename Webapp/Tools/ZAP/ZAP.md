---
id: ZAP
aliases:
  - Zed Attack Proxy
tags:
  - Webapp/Tools/ZAP/ZAP
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

# Zed Attack Proxy

[Zed Attack Proxy](https://www.zaproxy.org/)
is the world’s most widely used web app scanner

<!-- Install {{{-->
## Install

[Kali Tools - zaproxy](https://www.kali.org/tools/zaproxy/)

```sh
sudo apt install zaproxy
```

___
<!-- }}} -->

<!-- Configuration {{{-->
## Configuration

<!-- Dark Theme {{{-->
### Dark Theme

```sh
Tools > Options > Display > Look and Feel
```

<!-- }}} -->

<!-- Proxy Listener {{{-->
### Proxy Listener

```sh
Tools > Options > Network > Local Servers / Proxies
```

<!-- CA Certificate {{{-->
#### CA Certificate

```sh
Tools > Options > Network > Server Certificates
```

<!-- Example {{{-->
> [!example]-
>
> ![[ca-certificate-zap.png]]
<!-- }}} -->

<!-- Firefox Import {{{-->
##### Firefox Import

1. Open Certificate Manager

```sh
Settings > Certificates > View Certificates...
```

<!-- Example {{{-->
> [!example]-
>
> ![[ca-certificate-view.png]]
<!-- }}} -->

2. Import Certificate

<!-- Example {{{-->
> [!example]-
>
> ![[ca-certificate-manager.png]]
<!-- }}} -->

3. Trust Certificate

<!-- Example {{{-->
> [!example]-
>
> ![[ca-certificate-trust.png]]
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- Scope {{{-->
### Scope

Include a target in the scope

```sh
File > Session Properties > Contexts / Default Context > Include in context
```

<!-- Example {{{-->
> [!example]-
>
> ![[context-scope.png]]
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Proxy {{{-->
## Proxy

<!-- HUD {{{-->
### HUD

> [!todo]

<!-- }}} -->

<!-- Automatic Modification {{{-->
### Automatic Modification

<!-- Request {{{-->
#### Request

Automatic Request Modification

```sh
Tools > Replacer Options (Ctrl+R)
```
```sh
Tools > Options > Replacer
```

<!-- Example {{{-->
> [!example]-
>
> ![[match-replace.png]]
<!-- }}} -->

<!-- }}} -->

<!-- Response {{{-->
#### Response



<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->


<!-- Fuzzer {{{-->
## Fuzzer


___
<!-- }}} -->

<!-- Scanner {{{-->
## Scanner


___
<!-- }}} -->
