---
id: Proxy
aliases:
  - ZAP Proxy
tags:
  - Webapp/Tools/ZAP/Proxy
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

# ZAP Proxy

<!-- Configuration {{{-->
## Configuration

<!-- Context {{{-->
### Context

[Contexts](https://www.zaproxy.org/docs/desktop/start/features/contexts/)
are a way of relating a set of URLs together

[Contexts](https://www.zaproxy.org/docs/desktop/start/features/contexts/)
are defined as a set of regular expressions
which are applied to all of the URLs in the
[Sites Tree](https://www.zaproxy.org/docs/desktop/start/features/sitestree/)

<!-- }}} -->

<!-- Scope {{{-->
### Scope

The [Scope](https://www.zaproxy.org/docs/desktop/start/features/scope/)
is a set of URLs being tested and is defined by the
[context](https://www.zaproxy.org/docs/desktop/start/features/contexts/)

Include a target in the scope

```sh
File > Session Properties > Contexts / Default Context > Include in context
```

Define a target with regex

<!-- Tip {{{-->
> [!tip]
>
> The regular expressions must match the entire URL
<!-- }}} -->

```sh
http://<target_ip>[:<target_port>].*
```

<!-- Example {{{-->
> [!example]-
>
> ![[context-scope.png]]
<!-- }}} -->

Display only target request

<!-- }}} -->

<!-- Proxy Listener {{{-->
### Proxy Listener

Set up a proxy listener

```sh
Tools > Options > Network > Local Servers / Proxies
```

> [!example]-
>
> ![[proxy-listener.png]]

<!-- CA Certificate {{{-->
#### CA Certificate

**EXPORT CA CERTIFICATE**

Export ZAP's CA certificate

```sh
Tools > Options > Network > Server Certificates
```

<!-- Example {{{-->
> [!example]-
>
> ![[ca-certificate-zap.png]]
<!-- }}} -->

**FIREFOX IMPORT**

Import ZAP's CA certificate to Firefox

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

___
<!-- }}} -->

<!-- Intercept {{{-->
## Intercept

1. Set [[#Context]]

2. Set [[#Scope]]

3. Intercept traffic

Toggle Request Interception

```sh
CTRL + B
```

```sh
Tools > Toggle Break on All Requests
```

<!-- Example {{{-->
> [!example]-
>
> ![[proxy-toggle.png]]
<!-- }}} -->

___
<!-- }}} -->

<!-- Modify {{{-->
## Modify

[Manual Request Editor](https://www.zaproxy.org/docs/desktop/addons/requester/dialogs/) —
Send the request to the Request Editor

1. Open the Manual Request Editor

```sh
CTRL + M
```

```sh
Tools > Manual Request Editor...
```

```sh
Context > Open/Resend with Request Editor
```

> [!example]-
>
> ![[proxy-request-editor.png]]

[Replacer](https://www.zaproxy.org/docs/desktop/addons/replacer/) —
Automatic Request Modification

```sh
CTRL + R
```

```sh
Tools > Replacer Options
```
```sh
Tools > Options > Replacer
```

<!-- Example {{{-->
> [!example]-
>
> ![[proxy-match-replace.png]]
<!-- }}} -->

___
<!-- }}} -->

<!-- HUD {{{-->
## HUD

> [!todo]

___
<!-- }}} -->

<!-- Encode {{{-->
## Encode

[Encode / Decode / Hash](https://www.zaproxy.org/docs/desktop/addons/encode-decode-hash/)

```sh
CTRL + E
```

```sh
Tools > Encode/Decode/Hash
```

<!-- Example {{{-->
> [!example]-
>
> ![[encode-decode-hash.png]]
<!-- }}} -->

___
<!-- }}} -->
