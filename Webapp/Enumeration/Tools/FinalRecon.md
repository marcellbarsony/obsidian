---
id: FinalRecon
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/FinalRecon
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# FinalRecon

___

<!-- Installation {{{-->
## Installation

Install FinalRecon manually with [pip](https://pypi.org/project/pip/)

<!-- Example {{{-->
> [!example]-
>
> ```sh
> clone https://github.com/thewhiteh4t/FinalRecon.git
> ```
> ```sh
> cd FinalRecon
> ```
> ```sh
> pip3 install -r requirements.txt
> ```
> ```sh
> chmod +x ./finalrecon.py
> ```
<!-- }}} -->

Validate FinalRecon installation with the `--help` flag

```sh
./finalrecon.py --help
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ./finalrecon.py --help
> ```
> ```sh
> usage: finalrecon.py [-h] [--url URL] [--headers] [--sslinfo] [--whois]
>                      [--crawl] [--dns] [--sub] [--dir] [--wayback] [--ps]
>                      [--full] [-nb] [-dt DT] [-pt PT] [-T T] [-w W] [-r] [-s]
>                      [-sp SP] [-d D] [-e E] [-o O] [-cd CD] [-k K]
>
> FinalRecon - All in One Web Recon | v1.1.6
>
> optional arguments:
>   -h, --help  show this help message and exit
>   --url URL   Target URL
>   --headers   Header Information
>   --sslinfo   SSL Certificate Information
>   --whois     Whois Lookup
>   --crawl     Crawl Target
>   --dns       DNS Enumeration
>   --sub       Sub-Domain Enumeration
>   --dir       Directory Search
>   --wayback   Wayback URLs
>   --ps        Fast Port Scan
>   --full      Full Recon
>
> Extra Options:
>   -nb         Hide Banner
>   -dt DT      Number of threads for directory enum [ Default : 30 ]
>   -pt PT      Number of threads for port scan [ Default : 50 ]
>   -T T        Request Timeout [ Default : 30.0 ]
>   -w W        Path to Wordlist [ Default : wordlists/dirb_common.txt ]
>   -r          Allow Redirect [ Default : False ]
>   -s          Toggle SSL Verification [ Default : True ]
>   -sp SP      Specify SSL Port [ Default : 443 ]
>   -d D        Custom DNS Servers [ Default : 1.1.1.1 ]
>   -e E        File Extensions [ Example : txt, xml, php ]
>   -o O        Export Format [ Default : txt ]
>   -cd CD      Change export directory [ Default : ~/.local/share/finalrecon ]
>   -k K        Add API key [ Example : shodan@key ]
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Run FinalRecon, retrieve headers and perform [[Domain#WHOIS|WHOIS]] lookup

```sh
./finalrecon.py --headers --whois --url http://<target>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ./finalrecon.py --headers --whois --url http://inlanefreight.com
> ```
> ```sh
>
>  ______  __   __   __   ______   __
> /\  ___\/\ \ /\ "-.\ \ /\  __ \ /\ \
> \ \  __\\ \ \\ \ \-.  \\ \  __ \\ \ \____
>  \ \_\   \ \_\\ \_\\"\_\\ \_\ \_\\ \_____\
>   \/_/    \/_/ \/_/ \/_/ \/_/\/_/ \/_____/
>  ______   ______   ______   ______   __   __
> /\  == \ /\  ___\ /\  ___\ /\  __ \ /\ "-.\ \
> \ \  __< \ \  __\ \ \ \____\ \ \/\ \\ \ \-.  \
>  \ \_\ \_\\ \_____\\ \_____\\ \_____\\ \_\\"\_\
>   \/_/ /_/ \/_____/ \/_____/ \/_____/ \/_/ \/_/
>
> [>] Created By   : thewhiteh4t
>  |---> Twitter   : https://twitter.com/thewhiteh4t
>  |---> Community : https://twc1rcle.com/
> [>] Version      : 1.1.6
>
> [+] Target : http://inlanefreight.com
>
> [+] IP Address : 134.209.24.248
>
> [!] Headers :
>
> Date : Tue, 11 Jun 2024 10:08:00 GMT
> Server : Apache/2.4.41 (Ubuntu)
> Link : <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/", <https://www.inlanefreight.com/index.php/wp-json/wp/v2/pages/7>; rel="alternate"; type="application/json", <https://www.inlanefreight.com/>; rel=shortlink
> Vary : Accept-Encoding
> Content-Encoding : gzip
> Content-Length : 5483
> Keep-Alive : timeout=5, max=100
> Connection : Keep-Alive
> Content-Type : text/html; charset=UTF-8
>
> [!] Whois Lookup :
>
>    Domain Name: INLANEFREIGHT.COM
>    Registry Domain ID: 2420436757_DOMAIN_COM-VRSN
>    Registrar WHOIS Server: whois.registrar.amazon.com
>    Registrar URL: http://registrar.amazon.com
>    Updated Date: 2023-07-03T01:11:15Z
>    Creation Date: 2019-08-05T22:43:09Z
>    Registry Expiry Date: 2024-08-05T22:43:09Z
>    Registrar: Amazon Registrar, Inc.
>    Registrar IANA ID: 468
>    Registrar Abuse Contact Email: abuse@amazonaws.com
>    Registrar Abuse Contact Phone: +1.2024422253
>    Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
>    Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
>    Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
>    Name Server: NS-1303.AWSDNS-34.ORG
>    Name Server: NS-1580.AWSDNS-05.CO.UK
>    Name Server: NS-161.AWSDNS-20.COM
>    Name Server: NS-671.AWSDNS-19.NET
>    DNSSEC: unsigned
>    URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>
>
> [+] Completed in 0:00:00.257780
>
> [+] Exported : /home/htb-ac-643601/.local/share/finalrecon/dumps/fr_inlanefreight.com_11-06-2024_11:07:59
> ```
<!-- }}} -->

___
<!-- }}} -->
