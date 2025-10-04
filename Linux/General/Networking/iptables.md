---
id: iptables
aliases: []
tags:
  - Linux/General/Networking/iptables
---

# iptables

**[iptables](https://wiki.archlinux.org/title/Iptables)** is a command line
utility for configuring Linux kernel firewall implemented within the
[Netfilter](https://www.netfilter.org/) project.
**iptables** is also commonly used to refer to the kernel-level firewall.

## Installation

The stock Arch Linux kernel is compiled with **iptables** support. Only userland
utilities need to be installed. The [iptables package](https://archlinux.org/packages/core/x86_64/iptables/)
is an indirect dependency of the [base meta package](https://archlinux.org/packages/core/any/base/).

## Basic concepts

**iptables** is used to inspect, modify, forward, redirect, and/or drop IP
packets. The code for filtering IP packets is already built into the kernel and
is organized into a collection of tables, each with a specific purpose.
