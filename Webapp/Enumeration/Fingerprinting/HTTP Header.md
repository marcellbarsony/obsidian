---
id: HTTP Header
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/HTTP-Header
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---


# HTTP Headers

The [[Webapp/General/HTTP/HTTP Header]] fields define the operating parameters
of an [[HTTP/General|HTTP]] transaction

___

<!-- Inspect {{{-->
## Inspect

Enumerate [[Webapp/General/HTTP/HTTP Header|HTTP Response Headers]]
to reveal technologies used (*e.g., [[CMS]]*)

Inspect HTTP headers in the browser

1. Inspect webpage

```sh
Ctrl + Shift + I
```

2. Select the `Network` tab

```sh
Ctrl + Shift + E
```

3. Reload the page

```sh
F5
```

<!-- Example {{{-->
> [!example]-
>
> ![[inspect-browser.png]]
>
<!-- }}} -->

[[cURL]] — Grab banner

```sh
curl -I http://$target
```

<!-- Example {{{-->
> [!example]-
>
> Grab the banner of `inlanefreight.com`
>
> ```sh
> curl -I https://inlanefreight.com
> ```
> ```sh
> HTTP/1.1 301 Moved Permanently
> Date: Fri, 31 May 2024 12:12:12 GMT
> Server: Apache/2.4.41 (Ubuntu)
> X-Redirect-By: WordPress
> Location: https://www.inlanefreight.com/
> Content-Type: text/html; charset=UTF-8
> ```
>
> - `inlanefreight.com` is running on `Apache/2.4.41 (Ubuntu)`
> - `WordPress` is redirecting to `https://www.inlanefreight.com/`
>
> ```sh
> curl -I https://www.inlanefreight.com
> ```
> ```sh
> HTTP/1.1 200 OK
> Date: Fri, 31 May 2024 12:12:26 GMT
> Server: Apache/2.4.41 (Ubuntu)
> Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
> Link: <https://www.inlanefreight.com/index.php/wp-json/wp/v2/pages/7>; rel="alternate"; type="application/json"
> Link: <https://www.inlanefreight.com/>; rel=shortlink
> Content-Type: text/html; charset=UTF-8
> ```
>
> - `/wp-json` is a WordPress path worth further investigation
<!-- }}} -->

Grab banner & web server headers

```sh
curl -IL http://$target
```

Spoof [[User Agent]] and follow redirects

```sh
curl -A "Custom user-agent" -L http://$target
```

[[Netcat]] — Grab banner

1. Establish connections

```sh
ncat $target 80
```

2. Then type

```sh
HEAD / HTTP/1.0
Host: $target
```

___
<!-- }}} -->

<!-- Web Tools {{{-->
## Web Tools

Enumerate headers with web tools

- [Security Headers](https://securityheaders.com/)
- [WebSniffer](https://websniffer.com/)

___
<!-- }}} -->
