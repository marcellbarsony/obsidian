---
id: ICMP
aliases:
  - Internet Control Message Protocol
tags:
  - Networking
  - Layer-3
  - ICMP
links: "[[Layer-3]]"
---

# ICMP

[Internet Control Message Protocol](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
is used to communicate for various purposes, including error reporting and
status information.

## ICMP Messages

An ICMP message is either an ICMP **request** or a **reply**.

ICMP has two different versions:

- **ICMPv4**: For IPv4 only
- **ICMPv6**: For IPv6 only

### ICMP Requests

An ICMP request is a message sent by one device to another to request information or
perform a specific action.

| Request Type | Description |
| ------------ | ----------- |
| Echo Request | Tests whether a device is reachable on the network. When a device sends an echo request, it expects to receive an echo reply message. For example, the tools tracert (Windows) or traceroute (Linux) always send ICMP echo requests. |
| Timestamp Request | Determines the time on a remote device. |
| Address Mask Request | Used to request the subnet mask of a device. |

### ICMP Reply

| Message Type | Description |
| ----------- | -------------- |
| Echo reply | Sent in response to an echo request message. |
| Destination unreachable | Sent when a device cannot deliver a packet to its destination. |
| Redirect | A router sends this message to inform a device that it should send its packets to a different router. |
| time exceeded | Sent when a packet has taken too long to reach its destination. |
| Parameter problem | Sent when there is a problem with a packet's header. |
| Source quench | Sent when a device receives packets too quickly and cannot keep up. It is used to slow down the flow of packets. |
