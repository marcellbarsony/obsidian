---
id: Nikto
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Nikto
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Nikto

[Nikto](https://github.com/sullo/nikto) is an open-source web server scanner

___

<!-- Install {{{-->
## Install

Install [Perl](https://www.perl.org/) and clone **Nikto**

> [!example]-
>
> ```sh
> sudo apt update && sudo apt install -y perl
> ```
>
> ```sh
> git clone https://github.com/sullo/nikto
> ```
>
> ```sh
> cd nikto/program
> ```
>
> ```sh
> chmod +x ./nikto.pl
> ```

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Fingerprint a website

```sh
nikto -h <target> -Tuning b
```

> [!info]-
>
> - `-h`: Specify target host
> - `-Tuning b`: Run the Software Identification modules only

<!-- Example {{{-->
> [!example]-
>
> ```sh
> nikto -h inlanefreight.com -Tuning b
> ```
> ```sh
> - Nikto v2.5.0
> ---------------------------------------------------------------------------
> + Multiple IPs found: 134.209.24.248, 2a03:b0c0:1:e0::32c:b001
> + Target IP:          134.209.24.248
> + Target Hostname:    www.inlanefreight.com
> + Target Port:        443
> ---------------------------------------------------------------------------
> + SSL Info:        Subject:  /CN=inlanefreight.com
>                    Altnames: inlanefreight.com, www.inlanefreight.com
>                    Ciphers:  TLS_AES_256_GCM_SHA384
>                    Issuer:   /C=US/O=Let's Encrypt/CN=R3
> + Start Time:         2024-05-31 13:35:54 (GMT0)
> ---------------------------------------------------------------------------
> + Server: Apache/2.4.41 (Ubuntu)
> + /: Link header found with value: ARRAY(0x558e78790248). See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
> + /: The site uses TLS and the Strict-Transport-Security HTTP header is not defined. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
> + /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
> + /index.php?: Uncommon header 'x-redirect-by' found, with contents: WordPress.
> + No CGI Directories found (use '-C all' to force check all possible dirs)
> + /: The Content-Encoding header is set to "deflate" which may mean that the server is vulnerable to the BREACH attack. See: http://breachattack.com/
> + Apache/2.4.41 appears to be outdated (current is at least 2.4.59). Apache 2.2.34 is the EOL for the 2.x branch.
> + /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
> + /license.txt: License file found may identify site software.
> + /: A Wordpress installation was found.
> + /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
> + /wp-login.php:X-Frame-Options header is deprecated and has been replaced with the Content-Security-Policy HTTP header with the frame-ancestors directive instead. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
> + /wp-login.php: Wordpress login found.
> + 1316 requests: 0 error(s) and 12 item(s) reported on remote host
> + End Time:           2024-05-31 13:47:27 (GMT0) (693 seconds)
> ---------------------------------------------------------------------------
> + 1 host(s) tested
> ```
>
> > [!info]
> >
> > - **IPs**: The website resolves to both IPv4 (134.209.24.248) and IPv6 (2a03:b0c0:1:e0::32c:b001) addresses.
> > - **Server Technology**: The website runs on Apache/2.4.41 (Ubuntu)
> > - **WordPress Presence**: The scan identified a WordPress installation, including the login page (/wp-login.php). This suggests the site might be a potential target for common WordPress-related exploits.
> > - **Information Disclosure**: The presence of a license.txt file could reveal additional details about the website's software components.
> > - **Headers**: Several non-standard or insecure headers were found, including a missing Strict-Transport-Security header and a potentially insecure x-redirect-by header.
<!-- }}} -->

Scan a website

```sh
nikto -h http://<target>
```

> [!example]-
>
> ```sh
> nikto -h http://example.com
> ```

___
<!-- }}} -->
