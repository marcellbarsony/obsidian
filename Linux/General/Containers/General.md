---
id: General
aliases: []
tags:
  - Linux/General/Containers
links: "[[Containers]]"
---

# Containers

**Containers** operate at the operating system level
and virtual machines at the hardware leve

<!-- Example {{{-->
> [!example]-
>
> ![[containers-vms.png]]
<!-- }}} -->

___

<!-- LXC {{{-->
## LXC

**Linux Containers** (*[LXC](https://en.wikipedia.org/wiki/LXC)*)
is an operating system-level virtualization method
for running multiple isolated Linux systems (*containers*)
on a control host using a single Linux kernel

<!-- LXD {{{-->
### LXD

**Linux Daemon** (*[LXD](https://github.com/lxc/incus)*)
is an alternative Linux container manager, written in Go.
**LXD** is built on top of [[#LXC]]
and aims to provide a better user experience.

**LXD** is Ubuntu's default container manager
(*similar to Docker*)

<!-- }}} -->

___
<!-- }}} -->
