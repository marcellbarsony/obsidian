---
id: General
aliases: "Intrusion Detection & Prevention System"
links:
  - "[[Networking/General/General|General]]"
tags:
  - Networking/General/IDS-IPS
---

# IPS & IDS

**Intrusion Detection** and **Prevention Systems**
([IDS](https://www.ibm.com/think/topics/intrusion-detection-system)/
[IPS](https://www.ibm.com/think/topics/intrusion-prevention-system))
are security solutions designed to monitor and respond to suspicious network or
system activity.

An **Intrusion Detection System** ([IDS](https://www.ibm.com/think/topics/intrusion-detection-system))
observes traffic or system events to identify malicious behavior or policy
violations, generating alerts but not blocking the suspicious traffic.

An **Intrusion Prevention System** ([IPS](https://www.ibm.com/think/topics/intrusion-prevention-system))
operates similarly to an IDS, but takes an additional step by preventing or
rejecting malicious traffic in real time.

**IDS**/**IPS** can be placed at several strategic locations in a network:

- **Behind the firewall**, where **IPS**/**IDS** inspects any remaining traffic
- **In the DMZ**, where they monitor traffic moving in and out of publicly
  accessible servers


## IPS & IDS Types

### Network-based

Hardware device or software solution placed at strategic points in the network
to inspect all passing traffic

> [!example]
>
> A sensor connected to the core switch that monitors traffic within a data
> center

### Host-based

Runs on individual hosts or devices, monitoring inbound/outbound traffic and
system logs for suspicious behavior on that specific machine

> [!example]
>
> An antivirus or endpoint security agent installed on a server

## Best Practices

| Practice                     | Description |
| ---------------------------- | ----------- |
| Define Clear Policies        | Consistent firewall rules based on the principle of least privilege |
| Regular Updates              | Keep firewall, IDS/IPS signatures, and operating systems up to date |
| Monitor and Log Events       | Regularly review firewall logs, IDS/IPS alerts, and system logs to identify suspicious patterns early |
| Layered Security             | Use defense in depth with multiple layers: Firewalls, IDS/IPS, antivirus, and endpoint protection |
| Periodic Penetration Testing | Test the effectiveness of the security policies and devices by simulating real attacks |
