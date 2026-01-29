---
id: Go
aliases: []
tags:
  - Pentest/Brute-Force
---

# Go

[Go](https://go.dev/)
is a high-level, general-purpose programming language
that is statically-typed and compiled

It is syntactically similar to [[C/General|C]],
but also has garbage collection, structural typing,
and CSP-style concurrency

___

<!-- Install {{{-->
## Install

[Download and install](https://go.dev/doc/install)

1. Remove any previous Go installation

```sh
 rm -rf /usr/local/go && tar -C /usr/local -xzf go1.25.6.linux-amd64.tar.gz
```

2. Add `/user/local/go/bin` to the [[PATH]]

```sh
export PATH=$PATH:/usr/local/go/bin
```

3. Install Go

```sh
sudo apt install go -y
```

4. Verify installation

```sh
go version
```

___
<!-- }}} -->
