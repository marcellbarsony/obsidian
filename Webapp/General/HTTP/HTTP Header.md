---
id: HTTP Header
aliases: []
tags:
  - Webapp/General/HTTP-Header
---

# HTTP Header

[HTTP Headers](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields)
let the client and the server pass additional information
with a message in a request or response

<!-- Info {{{-->
> [!info]- Resources
>
> Mozilla Developer Network (*MDN*) Notes
>
> - [HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers)
> - [Request Headers](https://developer.mozilla.org/en-US/docs/Glossary/Request_header)
> - [Response Headers](https://developer.mozilla.org/en-US/docs/Glossary/Response_header)
> - [Payload Headers](https://developer.mozilla.org/en-US/docs/Glossary/Payload_header)
> - [Representation Header](https://developer.mozilla.org/en-US/docs/Glossary/Representation_header)
>
<!-- }}} -->

In `HTTP/1.X`, a header is a case-insensitive name followed by a colon

```sh

```

> [!todo]

___

<!-- HTTP Request Header {{{-->
## HTTP Request Header


___
<!-- }}} -->

<!-- HTTP Response Header {{{-->
## HTTP Response Header

A [Response Header](https://developer.mozilla.org/en-US/docs/Glossary/Response_header)
is an HTTP header that can be used in an HTTP response
and that doesn't relate to the content of the message

<!-- multipart/form-data {{{-->
### multipart/form-data

<!-- Info {{{-->
> [!info]- Resources
>
> - [Medium - Understanding multipart/form-data: The Ultimate Guide for Beginners](https://medium.com/@muhebollah.diu/understanding-multipart-form-data-the-ultimate-guide-for-beginners-fd039c04553d)
>
<!-- }}} -->

```sh
multipart/form-data
```

> [!todo]

<!-- }}} -->

<!-- X-Powered-By {{{-->
### X-Powered-By

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

<!-- }}} -->

<!-- X-Runtime {{{-->
### X-Runtime

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

<!-- }}} -->

___
<!-- }}} -->

<!-- HTTP Representation Header {{{-->
## HTTP Representation Header

A [Representation Header](https://developer.mozilla.org/en-US/docs/Glossary/Representation_header)
(*or 'representation metadata'*) is an HTTP header
that describes how to interpret the data contained in the message

<!-- Content-Type {{{-->
### Content-Type

> [!todo]

```sh
Content-Type: application/x-www-form-urlencoded
```

<!-- }}} -->

<!-- MIME Type {{{-->
### MIME Type

A [MIME Type](https://developer.mozilla.org/en-US/docs/Glossary/MIME_type)
(*or "media type" and sometimes "content type"*)
is a string sent along with a file indicating the type of the file

```sh
MIME-Type: image/png
```

<!-- }}} -->

___
<!-- }}} -->
