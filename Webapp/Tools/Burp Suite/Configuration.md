---
id: Burp Suite
aliases: []
tags:
  - Webapp/Tools/Burp-Suite/Burp-Suite/Configuration
links: "[[Webapp/Enumeration/Tools|Tools]]"
---

# Burp Suite Configuration

<!-- HTTPS {{{-->
## HTTPS

Install Burp's CA Certificate for HTTPs traffic

1. Set Burp as a proxy in the browser

2. Visit [http://burp](http://burp) and [download](http://burp/cert)
   the CA Certificate

![[ca-certificate-download.png]]

### Firefox

1. Open Certificate Manager: Settings > Certificates > View Certificates...

![[ca-certificate-view.png]]

2. Import Certificate

![[ca-certificate-manager.png]]

3. Trust Certificate

![[ca-certificate-trust.png]]

<!-- }}} -->
