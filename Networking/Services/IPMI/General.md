---
id: General
aliases: []
tags:
  - Networking/Services/IPMI/General
links: "[[Services]]"
port:
  - UDP/623
---

# IPMI

**IPMI** ([Intelligent Platform Management Interface](https://en.wikipedia.org/wiki/Intelligent_Platform_Management_Interface))
is a set of standardized specifications for for an autonomous computer subsystem
that provides management and monitoring capabilities independently of the host
system's CPU, firmware (BIOS or UEFI) and operating system.

**IPMI** provides sysadmins with the ability to manage and monitor systems,
even if they are powered off or in an unresponsive state, via direct connection
to the system's hardware.

<!-- BMC {{{-->
## BMC

**BMC** ([Baseboard Management Controller](https://www.supermicro.com/en/glossary/baseboard-management-controller))
is a specialized microcontroller embedded on the motherboard of servers
that provides the intelligence in the **IPMI** architecture.

Many **BMC**s expose a web-based management console, some sort of command-line
remote access protocol (such as [[Networking/Services/Telnet/General|Telnet]]
or [[Networking/Services/SSH/General|SSH]]), and the port UDP/`623`,
which is for the **IPMI** network protocol.

The most common [BMC](https://www.supermicro.com/en/glossary/baseboard-management-controller)s are

- [HP iLO](https://en.wikipedia.org/wiki/HPE_Integrated_Lights-Out)
- [Dell DRAC](https://en.wikipedia.org/wiki/Dell_DRAC)
- [Supermicro IPMI](https://www.supermicro.com/en/solutions/management-software/bmc-resources)
<!-- }}} -->

<!-- Usage {{{-->
## Usage

**IPMI** is typically used in three ways:

1. Before the OS has booted to modify BIOS settings
2. When the host is fully powered down
3. Access to a host after a system failure

**IPMI** can also

- Monitor different things (e.g., *temperature*, *voltage*, *fan status*,
  *power supplies*)
- Query inventory information
- Review hardware logs
<!-- }}} -->

## Configuration

> [!todo]

### Dangerous Settings

> [!todo]
