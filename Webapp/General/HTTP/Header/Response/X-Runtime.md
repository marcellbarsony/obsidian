---
id: X-Runtime
aliases: []
tags:
  - Webapp/General/HTTP/Header/Response/X-Runtime
---

# X-Runtime

`X-Runtime` usually disclosing runtime version details

```sh
X-Runtime: Ruby
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
> <!-- }}} -->
