---
id: _Checklist
aliases: []
tags:
  - Webapp/Enumeration/Checklist
---

# Web Application Enumeration Checklist

___

<!-- Domain {{{-->
## Domain

- [ ] [[Domain]]
    - [ ] [[Domain#WHOIS|WHOIS]]
    - [ ] [[Domain#DNS|DNS]]
        - [ ] [[DNS/Enumeration#Subdomain Brute Forcing|Subdomain Brute Forcing]]
        - [ ] [[DNS/Enumeration#AXFR Zone Transfer|AXFR Zone Transfer]]
    - [ ] [[Virtual Hosts]]
        - [ ] [[Virtual Hosts#Discovery|Discovery]]
        - [ ] [[Virtual Hosts#Banner Grabbing|Banner Grabbing]]
    - [ ] [[Domain#SSL Certificate|SSL Certificate]]
        - [ ] [[Domain#Certificate Transparency|Certificate Transparency]]

___
<!-- }}} -->

<!-- Fingerprinting {{{-->
## Fingerprinting

- [ ] [[Fingerprinting]]
    - [ ] [[Fingerprinting#Nmap Scan|Nmap Scan]]
        - [ ] [[Fingerprinting#Script Scan|Script Scan]]
    - [ ] [[Fingerprinting#Error Page|Error Page]]
    - [ ] [[Fingerprinting#Version Details & CVEs|Version Details & CVEs]]
        - [ ] [[Fingerprinting#Version Number|Version Number]]
        - [ ] [[Fingerprinting#Public Exploits|Public Exploits]]
    - [ ] [[Banner Grabbing#Banner Grabbing|Banner Grabbing]]
        - [ ] [[Banner Grabbing#cURL|cURL]]
        - [ ] [[Banner Grabbing#WhatWeb|WhatWeb]]
        - [ ] [[Banner Grabbing#Netcat|Netcat]]
    - [ ] [[Crawling]]
        - [ ] [[Crawling|#ReconSpider|ReconSpider]]
    - [ ] [[Wafw00f|WAF]]
        - [ ] [[Wafw00f|Wafw00f]]
    - [ ] [[Nikto]]

___
<!-- }}} -->

<!-- Execution paths {{{-->
## Execution paths

- [ ] [[Execution Paths]]
    - [ ] [[Execution Paths#Directory Structure|Directory Structure]]
        - [ ] [[Execution Paths#Directory Enumeration|Directory Enumeration]]
            - [ ] [[Burp Suite#Enumeration|Burp Suites]]
            - [ ] [[Dirsearch]]
            - [ ] [[Gobuster]]
            - [ ] [[Fuff]]
- [ ] [[Execution Paths#Investigate Findings|Investigate Findings]]

___
<!-- }}} -->

<!-- Metafiles {{{-->
## Metafiles

- [ ] [[Metafiles]]
    - [ ] [[Metafiles#humans.txt|humans.txt]]
    - [ ] [[Metafiles#robots.txt|robots.txt]]
    - [ ] [[Metafiles#sitemap.xml|sitemap.xml]]
- [ ] [[Well-Known]]
    - [ ] [[Well-Known#security.txt|security.txt]]
    - [ ] [[Well-Known#Change Password|change-password]]
    - [ ] [[Well-Known#OpenID Configuration|openid-configuration]]

___
<!-- }}} -->

<!-- Web contents {{{-->
## Web contents

- [ ] [[Web Contents]]
    - [ ] [[Web Contents#Page Source Code|Page Source Code]]
    - [ ] [[Web Contents#Autocompletion|Autocompletion]]
    - [ ] [[Web Contents#JavaScript Code|JavaScript Code]]

___
<!-- }}} -->

<!-- Application Functionality {{{-->
## Application Functionality

- [ ] [[Login Functionality|Login Functionality]]
    - [ ] [[Login Functionality#Discover Login Page|Discover Login Page]]

___
<!-- }}} -->
