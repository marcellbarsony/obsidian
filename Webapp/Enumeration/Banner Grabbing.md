---
id: Banner Grabbing
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Banner-Grabbing
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Banner Grabbing

[Banner Grabbing](https://en.wikipedia.org/wiki/Banner_grabbing)
is a technique used to gain information about a computer system on a network
and the services running on its open ports

___

<!-- cURL {{{-->
## cURL

Banner grabbing with [cURL](https://curl.se/)

```sh
curl -I http://<target>
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

Banner grabbing & Web server headers

```sh
curl -IL http://<target>
```

Spoof user agent and follow redirects

```sh
curl -A "Custom user-agent" -L http://<target>
```


___
<!-- }}} -->

<!-- Netcat {{{-->
## Netcat

[[Netcat]] — Grab banner

```sh
nc <target_url> 80
```

Then type

```sh
HEAD / HTTP/1.0
Host: <target_url>
```
___
<!-- }}} -->
