---
id: General
aliases: []
tags: []
---

# Firewall

A **Firewall** is a network security device (either hardware, software, or a
combination of both) that monitors incoming (*ingress*) and outgoing (*egress*)
network traffic.

- [Reddit - YSK about firewalls and how they work](https://www.reddit.com/r/networking/comments/ffblzq/ysk_about_firewalls_and_how_they_work/)
- [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/)

<!-- Firewall Types {{{-->
## Firewall Types

### Packet Filtering Firewall

Operates at Layer 3 (Network) and Layer 4 (Transport)

Examines source/destination IP, source/destination port, and protocol type.

> [!example]
>
> A simple router ACL that only allows HTTP (port 80) and HTTPS (port 443) while
> blocking other ports.

### Stateful Inspection Firewall

Tracks the state of network connections

They understand the entire conversation thus they are more intelligent

> [!example]
>
> Only allows inbound data that matches an already established outbound request.

### Application Layer Firewall (Proxy Firewall)

Operates up to Layer 7 (Application)

Can inspect the actual content of traffic (e.g., HTTP requests) and block
malicious requests.

> [!example]
>
> A web proxy that filters out malicious HTTP requests containing suspicious
> patterns.

### Next-Generation Firewalls (NGFW)

Combines stateful inspection with advanced features like deep packet inspection,
intrusion detection/prevention, and application control.

> [!example]
>
> A modern firewall that can block known malicious IP addresses, inspect
> encrypted traffic for threats, and enforce application-specific policies.

<!-- }}} -->
