---
id: Proxy
aliases: []
tags:
  - Webapp/Tools/Burp-Suite/Burp-Suite/Proxy
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

# Proxy

___

<!-- Configuration {{{-->
## Configuration

Configure Burp Suite proxy

### Proxy Listener

Configure a proxy listener

```sh
Proxy > Proxy settings > Tools > Proxy
```

> [!example]-
>
> ![[proxy-listener.png]]

<!-- Defaults {{{-->
> [!info]- Defaults
>
> Bind to port
>
> ```sh
> 8080
> ```
>
> Bind to address
>
> ```sh
> Loopback only
> ```
<!-- }}} -->

<!-- CA Certificate {{{-->
### CA Certificate

**EXPORT CERTIFICATE**

Install Burp's CA Certificate for HTTPs traffic

1. Set Burp as a proxy in the browser

2. Visit [http://burp](http://burp) and [download](http://burp/cert)
   the CA Certificate

<!-- Example {{{-->
> [!example]-
>
> ![[ca-certificate-download.png]]
<!-- }}} -->

**IMPORT CERTIFICATE**

**Firefox**

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

**Chromium**

> [!todo]

<!-- }}} -->

___
<!-- }}} -->

<!-- Scope {{{-->
## Scope

[Scope](https://portswigger.net/burp/documentation/desktop/tools/target/scope)
sets the URLs to test

- **Intercept** - Intercerpt and log in-scope requests only
- **Site Map** & **History** - Show in-scope items only
- [[Intruder]] & [[#Repeater]] - Follow in-scope URLs only

Add a target to the scope

```sh
Target > Scope > Add
```

<!-- Example {{{-->
> [!example]-
>
> ![[scope.png]]
<!-- }}} -->

**NORMAL SCOPE**

Quickly specify static prefixes for URLs

<!-- Warning {{{-->
> [!warning]
>
> Wildcard expressions are not supported in URL prefixes
> for normal scope control
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Valid URL prefixes
>
> ```sh
> http://example.com/path
> https://example.com/admin
> example.com
> example.com/myapp/
> http://example.com:8080/login
> ```
<!-- }}} -->

**ADVANCED SCOPE**

Advanced Scope settings

- **Protocol** - The protocol that the rule must match: `HTTP`, `HTTPS`,
  or `any`
- **Host or IP range** - A regular expression to match the hostname,
  or an IP range (*format: `10.1.1.1/24` or `10.1.1-20.1-127`*)
- **Port** - A regular expression to match one or more port numbers
- **File** - The file or path portion of the URL for the rule to match

___
<!-- }}} -->

<!-- Proxy {{{-->
## Proxy

<!-- Intercept {{{-->
### Intercept

Toggle proxy interception

```sh
Proxy > Intecrept > Intecrept on
```

> [!example]-
>
> ![[proxy-intercept.png]]

**Intercept Responses**

1. Open Proxy settings

```sh
Proxy > Proxy settings > Tools > Proxy > Response interception rules
```

2. Tick `Intecrept responses based on the following rules`

> [!example]-
>
> ![[proxy-intercept-responses.png]]


<!-- }}} -->

<!-- Modify {{{-->
### Modify

**REQUEST**

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

**RESPONSE**

Automatic Response Modification

```sh
Proxy > Match and replace
```
```sh
Proxy > Proxy settings > Tools > Proxy > HTTP match and replace rules
```

Modify the Type to `Response header` or `Response body`

<!-- Example {{{-->
> [!example]-
>
> ![[match-replace-response.png]]
<!-- }}} -->

<!-- }}} -->

<!-- Repeater {{{-->
### Repeater

[Burp Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater)
is a tool that enables to modify and send an interesting HTTP
or WebSocket message over and over

```sh
CTRL + SHIFT + R
```

```sh
CONTEXT > Send to Repeater
```

> [!example]-
>
> ![[repeater.png]]

<!-- }}} -->

___
<!-- }}} -->
