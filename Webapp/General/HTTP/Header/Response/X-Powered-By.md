---
id: X-Powered-By
aliases: []
tags:
  - Webapp/General/HTTP/Header/Response/X-Powered-By
---

# X-Powered-By

The [X-Powered-By response header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Powered-By)
is a non-standard header for identifying the application or framework
(*e.g. ASP.NET, PHP, JBoss*) that generated the response

```sh
X-Powered-By: PHP/5.4.0
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> curl -I http://precious.htb
> ```
> ```sh
> HTTP/1.1 200 OK
> Content-Type: text/html;charset=utf-8
> Content-Length: 483
> Connection: keep-alive
> Status: 200 OK
> X-XSS-Protection: 1; mode=block
> X-Content-Type-Options: nosniff
> X-Frame-Options: SAMEORIGIN
> Date: Mon, 19 Jan 2026 01:25:18 GMT
> X-Powered-By: Phusion Passenger(R) 6.0.15
> Server: nginx/1.18.0 + Phusion Passenger(R) 6.0.15
> X-Runtime: Ruby
> ```
<!-- }}} -->
