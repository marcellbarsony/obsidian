---
id: General
aliases:
  - Hypertext Transfer Protocol
tags:
  - Networking/Services/HTTP/General
links: "[[Services]]"
port:
  - 80
  - 443
---

# HTTP

**HTTP** ([Hypertext Transfer Protocol](https://en.wikipedia.org/wiki/HTTP))
is a stateless (but not sessionless) application layer protocol that is sent
over [TCP](https://developer.mozilla.org/en-US/docs/Glossary/TCP), or over a
[TLS](https://developer.mozilla.org/en-US/docs/Glossary/TLS)-encrypted TCP
connection.

<!-- Componets of HTTP-based systems {{{-->
## HTTP Componets

[Componets of HTTP-based systems](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#components_of_http-based_systems)

### Client

#### User-Agent

The [User-Agent](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#client_the_user-agent) is any tool that acts on behalf of the user - this role is
primarily performed by the Web browser.

### Web Server

The [Web Server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#the_web_server)
serves the document as requested by the client

### Proxies

[Proxies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#proxies)
are computers that relay the HTTP messages between a client and a server.

- **Transparent proxies** forward the requests they receive without altering
them in any way.

- **Non-transparent proxies** will change the requests in some way before
passing it along to the Server.

Proxies may perform numerous functions:
- **Caching** - the cache can be public or private, like the browser cache
- **Filtering** - like an antivirus scan or parental controls
- **Load balancing** - to allow multiple servers to serve different requests
- **Authentication** - to control access to different resources
- **Logging** - allowing the storage of historical information
<!--}}}-->

<!-- HTTP Flow {{{-->
## HTTP Flow

[HTTP Flow](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#http_flow)

1. **Open a TCP connection**: The TCP connection is used to send requests, and
   receive a response. The client may open a new connection, reuse an existing
   connection, or open several connections to the servers.

2. **Send a HTTP message**

> [!example]-
>
>```sh
>GET / HTTP/1.1
>Host: developer.mozilla.org
>Accept-Language: fr
>```

3. **Read the response sent by the server**

> [!example]-
>
>```sh
>HTTP/1.1 200 OK
>Date: Sat, 09 Oct 2010 14:28:02 GMT
>Server: Apache
>Last-Modified: Tue, 01 Dec 2009 20:18:22 GMT
>ETag: "51142bc1-7449-479b075b2891b"
>Accept-Ranges: bytes
>Content-Length: 29769
>Content-Type: text/html
>
><!doctype html>… (here come the 29769 bytes of the requested web page)
>```

4. **Close or reuse the connection** for further requests

### HTTP pipelining

If HTTP pipelining is activated, several requests can be sent without waiting
for the first response to be fully received. HTTP pipelining has been
superseded in HTTP/2 with more robust multiplexing requests within a frame.
<!--}}}-->

<!-- What can be controlled by HTTP {{{-->
## What can be controlled by HTTP

[What can be controlled by HTTP?](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#what_can_be_controlled_by_http)

The extensible nature of HTTP has allowed for more control and functionality of
the Web:

- **[Caching](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching)**
- **Relaxing the origin constraint**
- **Authentication**: Basic authentication may be provided by HTTP, either using the [WWW-Authenticate](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate)
  and similar headers, or by setting a specific session using [HTTP cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies).
- **[Proxy and tunneling](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling)**:
- **Sessions**

<!--}}}-->

<!-- HTTP Messages {{{-->
## HTTP Messages

[HTTP Messages](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#http_messages)
are the mechanism used to exchange data between a server and a client in the
HTTP protocol.

There are two types of messages:

- **Requests** sent by the client, to trigger an action on the server
- **Responses** the server sends to a request

<!-- Requests{{{-->
### Requests

[HTTP Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#requests)
should contain

1. The [HTTP method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) —
   definig the operation the client wants to perform
2. The **path** of the resource fo fetch — the URL of the resource stripped from
   elements
3. The **version** of the HTTP protocol

<!-- Example {{{-->
> [!example]-
>
> ```sh
> # [Method] [Path] [Protocol version]
> GET / HTTP/1.1
>
> # Headers
> Host: developer.mozilla.org
> Accept-Language: fr
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Responses {{{-->
### Responses

[HTTP Responses](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#responses)
should contain

1. The **version** of the HTTP protocol
2. The **status code**
3. The **status message**, non-authoritative short description of the status
4. The **HTTP headers**
5. Optionally, a body containing the **fetched resource**

<!-- Example {{{-->
> [!example]-
>
> ```sh
> # [Protocol version] [Status code] [Status message]
> HTTP/1.1 200 OK
>
> # Headers
> date: Sat, 09 Oct 2010 14:28:02 GMT
> cache-control: public, max-age=3600
> content-Type: text/html
> ```
<!-- }}} -->

<!--}}}-->

<!--}}}-->

## HTTP/1.1 vs. HTTP/2

> [!todo]

[Overview of HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Overview#http_messages)

HTTP messages, as defined in **HTTP/1.1** and earlier, are human-readable.

In **HTTP/2**, these messages are embedded into a binary structure, a frame,
allowing optimizations like compression of headers and multiplexing.

Even if only part of the original HTTP message is sent in this version of HTTP,
the semantics of each message is unchanged and the client reconstitutes
(virtually) the original HTTP/1.1 request.
It is therefore useful to comprehend HTTP/2 messages in the HTTP/1.1 format.

## HTTP Redirections

> [!todo]
