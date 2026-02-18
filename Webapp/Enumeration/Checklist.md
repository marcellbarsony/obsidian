---
id: _Checklist
aliases: []
tags:
  - Webapp/Enumeration/Checklist
---

# Web Application Enumeration Checklist

___

<!-- Passive Enumeration {{{-->
## Passive Enumeration

- [ ] [[Search Engine Discovery]]
- [ ] [[Public Archives]]
- [ ] [[Public Repositories]]

___
<!-- }}} -->

<!-- Infrastructure {{{-->
## Infrastructure

- [ ] [[Domain]]
    - [ ] [[Domain#WHOIS|WHOIS]]
    - [ ] [[Domain#Web Lookup|Web Lookup]]
- [ ] [[DNS]]
    - [ ] [[DNS/General#Subdomain|Subdomain]]
        - [ ] [[DNS/Enumeration#Search Engine Discovery|Search Engine Discovery]]
        - [ ] [[DNS/Enumeration#Certificate Transparency|Certificate Transparency]]
        - [ ] [[DNS/Enumeration#Passive Enumeration|Passive Enumeration]]
        - [ ] [[DNS/Enumeration#Brute Forcing|Brute Forcing]]
            - [ ] [[Ffuf#Subdomain|Subdomain Fuzzing]]
    - [ ] [[DNS/General#DNS Zone|DNS Zone]]
        - [ ] [[DNS/Enumeration#AXFR Zone Transfer|AXFR Zone Transfer]]
    - [ ] [[DNS/Enumeration#Automated Tools|Automated Tools]]
        - [ ] [[DNS/Tools/DNSRecon|DNSRecon]]
- [ ] [[VHost]]
    - [ ] [[VHost#Fuzzing|Fuzzing]]
        - [ ] [[Ffuf#Vhost Fuzzing|Vhost Fuzzing]]
    - [ ] [[VHost#Hosts|Hosts]]
    - [ ] [[VHost#Banner Grabbing|Banner Grabbing]]
        - [ ] [[VHost#Invalid Header|Invalid Header]]

___
<!-- }}} -->

<!-- Technologies {{{-->
## Technologies

- [ ] [[WAF]]
    - [ ] [[WAF#Identify|Identify]]
        - [ ] [[WAF#Nmap|Nmap]]
        - [ ] [[Wafw00f]]
        - [ ] [[WhatWaf]]
- [ ] [[CMS]]
    - [ ] [[CMS#Enumeration|Enumeration]]
        - [ ] [[CMS#Website|Website]]
        - [ ] [[CMS#Paths|Paths]]
        - [ ] [[CMS#Online Tools|Online Tools]]
        - [ ] [[CMS#Browser Extension|Browser Extension]]
        - [ ] [[CMS#HTML Tag|HTML Tag]]
        - [ ] [[CMS#Scan|Scan]]
            - [ ] [[Nikto]]
            - [ ] [[WPScan]]
            - [ ] [[Droopescan]]

___
<!-- }}} -->

<!-- Fingerprinting {{{-->
## Fingerprinting

- [ ] [[Webapp/Enumeration/Fingerprinting/General]]
    - [ ] [[Webapp/Enumeration/Fingerprinting/General#Version Details & CVEs|Version Details & CVEs]]
- [ ] [[Webapp/Enumeration/Fingerprinting/HTTP Header]]
    - [ ] [[Webapp/Enumeration/Fingerprinting/HTTP Header#HTTP Request|HTTP Request]]
    - [ ] [[Webapp/Enumeration/Fingerprinting/HTTP Header#Web Tools|Web Tools]]
- [ ] [[Error Page]]
    - [ ] [[Error Page#Get Error Page|Get Error Page]]
- [ ] [[Banner Grabbing#Banner Grabbing|Banner Grabbing]]
    - [ ] [[Banner Grabbing#cURL|cURL]]
    - [ ] [[Banner Grabbing#Netcat|Netcat]]
___
<!-- }}} -->

<!-- Vulnerabilities {{{-->
## Vulnerabilities

- [ ] [[Scanning]]
    - [ ] [[Nikto]]
    - [ ] [[WhatWeb]]
- [ ] [[Public Exploits]]
    - [ ] [[Public Exploits#Web|Web]]
    - [ ] [[Public Exploits#SearchSploit|SearchSploit]]

___
<!-- }}} -->

<!-- Discovery {{{-->
## Discovery

- [ ] [[Execution Paths]]
    - [ ] [[Execution Paths#Directory Structure|Directory Structure]]
        - [ ] [[Execution Paths#Directory Enumeration|Directory Enumeration]]
            - [ ] [[Burp Suite#Enumeration|Burp Suites]]
            - [ ] [[Dirsearch]]
            - [ ] [[Gobuster]]
                - [ ] [[Gobuster#Directory Enumeration|Directory Enumeration]]
            - [ ] [[Ffuf]]
                - [ ] [[Ffuf#Directory Fuzzing|Directory Fuzzing]]
                - [ ] [[Ffuf#Extension Fuzzing|Extension Fuzzing]]
        - [ ] [[Execution Paths#Recursive Directory Enumeration|Recursive Directory Enumeration]]
            - [ ] [[Burp Suite#Enumeration|Burp Suites]]
            - [ ] [[Dirsearch]]
            - [ ] [[Ffuf]]
                - [ ] [[Ffuf#Recursive|Recursive Fuzzing]]
            - [ ] [[Gobuster]]
                - [ ] [[Gobuster#Recursive Directory Enumeration|Recursive Directory Enumeration]]
    - [ ] [[Execution Paths#Page Enumeration|Page Enumeration]]
        - [ ] [[Ffuf]]
            - [ ] [[Ffuf#Page|Page Fuzzing]]
    - [ ] [[Execution Paths#Investigate Findings|Investigate Findings]]
- [ ] [[Crawling]]
    - [ ] [[ReconSpider]]
- [ ] [[Webapp/Enumeration/Discovery/Login Functionality]]

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
        - [ ] [[Web Contents#HTML Comments|HTML Comments]]
    - [ ] [[Web Contents#Autocompletion|Autocompletion]]
    - [ ] [[Web Contents#Hidden Fields|Hidden Fields]]

___
<!-- }}} -->
