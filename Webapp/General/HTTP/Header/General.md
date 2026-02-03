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

<!-- Example {{{-->
> [!example]-
>
> [[Apache HTTP Server/General|Apache]] response
>
> ```sh
> HTTP/1.1 200 OK
> Date: Thu, 05 Sep 2019 17:42:39 GMT
> Server: Apache/2.4.41 (Unix)
> Last-Modified: Thu, 05 Sep 2019 17:40:42 GMT
> ETag: "75-591d1d21b6167"
> Accept-Ranges: bytes
> Content-Length: 117
> Connection: close
> Content-Type: text/html
> ...
> ```
>
> [[Nginx/General|Nginx]] response
>
> ```sh
> HTTP/1.1 200 OK
> Server: nginx/1.17.3
> Date: Thu, 05 Sep 2019 17:50:24 GMT
> Content-Type: text/html
> Content-Length: 117
> Last-Modified: Thu, 05 Sep 2019 17:40:42 GMT
> Connection: close
> ETag: "5d71489a-75"
> Accept-Ranges: bytes
> ...
> ```
>
> lighttpd response
>
> ```sh
> HTTP/1.0 200 OK
> Content-Type: text/html
> Accept-Ranges: bytes
> ETag: "4192788355"
> Last-Modified: Thu, 05 Sep 2019 17:40:42 GMT
> Content-Length: 117
> Connection: close
> Date: Thu, 05 Sep 2019 17:57:57 GMT
> Server: lighttpd/1.4.54
> ```
<!-- }}} -->

___
