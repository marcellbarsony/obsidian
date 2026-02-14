---
id: OpenSSL
aliases: []
tags: []
---

# OpenSSL

[OpenSSL](https://www.openssl.org/)
is a robust, commercial-grade, full-featured Open Source Toolkit
for the Transport Layer Security (*TLS, formerly SSL*),
Datagram TLS (*DTLS*), and QUIC protocols

The protocol implementations are based on
a full-strength general purpose cryptographic library,
which can also be used stand-alone.

Also included is a cryptographic module validated
to conform with FIPS standards.

OpenSSL is descended from the SSLeay library
developed by Eric A. Young and Tim J. Hudson

___

<!-- Installation {{{-->
## Installation

[Kali Tools](https://www.kali.org/tools/openssl/)

```sh
sudo apt install openssl
```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Genrate 16 random bytes

```sh
openssl rand -hex 16
```

___
<!-- }}} -->
