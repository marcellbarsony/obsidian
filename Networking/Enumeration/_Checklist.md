---
id: Enumeration
aliases: []
tags:
  - Networking/Enumeration/Checklist
---

# Enumeration Checklist

___

<!-- Infrastructure Enumeration {{{-->
## Infrastructure Enumeration

- [ ] [[Domain Information]]
    - [ ] [[Domain Information#Subdomain Discovery|Subdomain Discovery]]
        - [ ] [[Domain Information#SSL Certificate|SSL Certificate]]
        - [ ] [[Domain Information#Shodan|Shodan]]
    - [ ] [[Domain Information#3rd Party Sites|3rd Party Sites]]
        - [ ] [[Domain Information#Domain.Glass|Domain.Glass]]
- [ ] [[DNS Records]]
    - [ ] TODO
- [ ] [[Cloud Resources]]
    - [ ] [[Cloud Resources#Google Dorks|Google Dorks]]
    - [ ] [[Cloud Resources#Website Source Code|Website Source Code]]
    - [ ] [[Cloud Resources#Cloud Storages|Cloud Storages]]
    - [ ] [[Cloud Resources#Leaked SSH Keys|Leaked SSH Keys]]
- [ ] [[Staff]]
    - [ ] [[Staff#LinkedIn|LinkedIn]]
    - [ ] [[Staff#GitHub|GitHub]]

___
<!-- }}} -->

<!-- Network Infrastructure {{{-->
## Network Infrastructure

- [ ] [[Detection Evasion#Firewall|Firewall]]
    - [ ] [[Detection Evasion#Firewall#Detection|Detection]]
        - [ ] [[Detection Evasion#Firewall#SYN Scan|SYN Scan]]
    - [ ] [[Detection Evasion#Fingerprint|Fingerprint]]
    - [ ] [[Detection Evasion#Firewall#Evasion|Evasion]]
        - [ ] [[Detection Evasion#Firewall#ACK Scan|ACK Scan]]
        - [ ] [[Detection Evasion#Firewall#UDP Scan|UDP Scan]]
- [ ] [[Detection Evasion#IPS/IDS|IPS/IDS]]
    - [ ] [[Detection Evasion#IPS/IDS#Detection|Detection]]
    - [ ] [[Detection Evasion#IPS/IDS#Evasion|Evasion]]
        - [ ] [[Detection Evasion#Decoys|Decoys]]
        - [ ] [[Detection Evasion#Different Source IP|Different Source IP]]
- [ ] [[Detection Evasion#DNS Proxying|DNS Proxying]]
    - [ ] [[Detection Evasion#Scan From DNS Port|Scan From DNS Port]]

___
<!-- }}} -->

<!-- Host Discovery {{{-->
## Host Discovery

- [ ] [[Host Discovery]]
    - [ ] [[Host Discovery#ARP Discovery|ARP Discovery]]
        - [ ] [[Host Discovery#netdiscover|netdiscover]]
        - [ ] [[Host Discovery#p0f|p0f]]
        - [ ] [[Host Discovery#bettercap|bettercap]]
    - [ ] [[Host Discovery#NBT Discovery|NBT Discovery]]
        - [ ] [[Host Discovery#nbtscan|nbtscan]]
    - [ ] [[Host Discovery#ICMP Echo Discovery|ICMP Echo Discovery]]
        - [ ] [[Nmap]]
            - [ ] [[Nmap/Host Discovery#Scan Network Range|Scan Network Range]]
            - [ ] [[Nmap/Host Discovery#Scan Multiple IPs|Scan Multiple IPs]]
            - [ ] [[Nmap/Host Discovery#Scan IP Range|Scan IP Range]]
            - [ ] [[Nmap/Host Discovery#Scan IP List|Scan IP List]]

___
<!-- }}} -->

<!-- Host Enumeration {{{-->
## Host Enumeration

- [ ] [[Host Enumeration|Host Enumeration]]
    - [ ] [[Host Enumeration#OS Detection|OS Detection]]
        - [ ] [[Host Enumeration#Basic Scan|Basic Scan]]
        - [ ] [[Host Enumeration#Version Scan|Version Scan]]
        - [ ] [[Host Enumeration#SYN Scan|SYN Scan]]
        - [ ] [[Host Enumeration#Aggerssive Scan|Aggerssive Scan]]
    - [ ] [[Host Enumeration#TCP Scan|TCP Scan]]
        - [ ] [[Host Enumeration#Top 10 TCP Port Scan|Top 10 TCP Port Scan]]
        - [ ] [[Host Enumeration#Open Port Discovery|Open Port Discovery]]
        - [ ] [[Host Enumeration#Full Port Scan|Full Port Scan]]
        - [ ] [[Host Enumeration#Script Scan|Script Scan]]
    - [ ] [[Host Enumeration#UDP Scan|UDP Scan]]
        - [ ] [[Host Enumeration#Top 100 UDP Ports|Top 100 UDP Ports]]
        - [ ] [[Host Enumeration#All UDP Ports|All UDP Ports]]
        - [ ] [[Host Enumeration#Specific UDP Port|Specific UDP Port]]

___
<!-- }}} -->

<!-- Service Enumeration {{{-->
## Service Enumeration

- [ ] [[Service Enumeration|Service Enumeration]]
    - [ ] [[Service Enumeration#Service Version Detection|Service Version Detection]]
    - [ ] [[Service Enumeration#Banner Grabbing|Banner Grabbing]]
        - [ ] [[Service Enumeration#Tcpdump|Tcpdump]]

___
<!-- }}} -->
