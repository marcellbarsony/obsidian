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
        - [ ] [[DNS/General#Subdomain|Subdomain]]
            - [ ] [[DNS/Enumeration#Search Engine Discovery|Search Engine Discovery]]
            - [ ] [[DNS/Enumeration#Certificate Transparency|Certificate Transparency]]
            - [ ] [[DNS/Enumeration#Passive Enumeration|Passive Enumeration]]
            - [ ] [[DNS/Enumeration#Brute Forcing|Brute Forcing]]
        - [ ] [[DNS/General#DNS Zone|DNS Zone]]
            - [ ] [[DNS/Enumeration#AXFR Zone Transfer|AXFR Zone Transfer]]
        - [ ] [[DNS/Enumeration#Automated Tools|Automated Tools]]
            - [ ] [[DNS/Tools/DNSRecon|DNSRecon]]
    - [ ] [[Virtual Hosts]]
        - [ ] [[Virtual Hosts#Discovery|Discovery]]
            - [ ] [[Virtual Hosts#Brute Force|Brute Force]]
        - [ ] [[Virtual Hosts#Banner Grabbing|Banner Grabbing]]

___
<!-- }}} -->

<!-- Fingerprinting {{{-->
## Fingerprinting

- [ ] [[Fingerprinting]]
    - [ ] [[WAF]]
        - [ ] [[WAF#Wafw00f|Wafw00f]]
        - [ ] [[WAF#Nmap|Nmap]]
        - [ ] [[WAF#WhatWaf|WhatWaf]]
    - [ ] [[Fingerprinting#Version Details & CVEs|Version Details & CVEs]]
        - [ ] [[HTTP Headers]]
            - [ ] [[HTTP Headers#HTTP Request|HTTP Request]]
        - [ ] [[Error Page]]
        - [ ] [[Fingerprinting#Nmap Scan|Nmap Scan]]
            - [ ] [[Fingerprinting#Script Scan|Script Scan]]
        - [ ] [[Banner Grabbing#Banner Grabbing|Banner Grabbing]]
            - [ ] [[Banner Grabbing#cURL|cURL]]
            - [ ] [[Banner Grabbing#Netcat|Netcat]]
        - [ ] [[Fingerprinting#Public Exploits|Public Exploits]]
            - [ ] [[SearchSploit]]
    - [ ] [[Crawling]]
        - [ ] [[ReconSpider]]
    - [ ] [[Scanning]]
        - [ ] [[Nikto]]
        - [ ] [[WhatWeb]]
    - [ ] [[CMS]]
        - [ ] [[CMS#Enumeration|Enumeration]]
            - [ ] [[CMS#Online Tools|Online Tools]]
            - [ ] [[CMS#WordPress|WordPress]]

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
            - [ ] [[Ffuf#Directory|Fuff]]
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
