---
id: Client Isolation
aliases: []
tags:
  - Networking/General/Wireless/Client-Isolation
---

# Client Isolation

Wireless **Client Isolation** prevents wireless clients from communicating with
each other when connected to the same SSID or WLAN.

- **Client Isolation** operates mainly at Layer 2 by filtering
  [[MAC-address]]-based traffic, so that wireless clients cannot send unicast
  frames to other clients directly on the same VLAN

- Each client can communicate only withe the default gateway or upstream router
  by whitelisting the default gateway MAC address and IP in the isolation
  whitelist


  DHCP and broadcast traffic are usually allowed to maintain network functions such as IP assignment and name resolution.

  The access point maintains a layer 2 firewall that blocks traffic from a wireless client destined for other wireless clients.

  In bridge mode, clients are bridged through the access point to the VLAN, but client isolation prevents direct Layer 2 connectivity between clients.

  Some advanced APs support exceptions for devices like printers or gateways by adding them to an isolation whitelist.

  Client isolation often relies on separate encryption keys: a unicast key per client prevents sharing traffic, and group keys for broadcast traffic remain for necessary shared communication.

  There are known bypass methods relying on manipulating ARP entries and multicast traffic, but advanced APs incorporate ARP control and stricter layer 2 isolation to counteract these.

Overall, wireless client isolation uses MAC-based filtering and packet
forwarding rules in the access point or wireless controller to enforce
client-to-client segmentation within the same wireless network, significantly
enhancing security in public or guest Wi-Fi environments while still allowing
upstream network access.
