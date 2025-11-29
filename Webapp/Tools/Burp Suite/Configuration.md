---
id: Burp Suite
aliases: []
tags:
  - Webapp/Tools/Burp-Suite/Burp-Suite/Configuration
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

# Burp Suite Configuration

___

<!-- Proxy Listeners {{{-->
## Proxy Listeners

Configure a proxy listener

```sh
Proxy > Options > Proxy Listeners
```

Interface: `127.0.0.1:8080`


<!-- CA Certificate {{{-->
### CA Certificate

Install Burp's CA Certificate for HTTPs traffic

1. Set Burp as a proxy in the browser

2. Visit [http://burp](http://burp) and [download](http://burp/cert)
   the CA Certificate

<!-- Example {{{-->
> [!example]-
>
> ![[ca-certificate-download.png]]
<!-- }}} -->

#### Firefox

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

___
<!-- }}} -->

<!-- Scope {{{-->
## Scope

Add a target to the scope

```sh
Target > Scope > Add
```

<!-- Example {{{-->
> [!example]-
>
> ![[scope.png]]
<!-- }}} -->

___
<!-- }}} -->
