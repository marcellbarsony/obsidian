---
id: Camaleon
aliases: []
tags:
  - Webapp
links:
---

# Camaleon CMS

[Camaleon CMS](https://github.com/owen2345/camaleon-cms)
is a dynamic and advanced content management system
based on [[Ruby/General|Ruby on Rails]]

___

<!-- General {{{-->
## General

Default Login page

```sh
http://$target.htb/admin/login
```

___
<!-- }}} -->

<!-- Vulnerabilities {{{-->
## Vulnerabilities

[CVE-2024-46986](https://nvd.nist.gov/vuln/detail/CVE-2024-46986)

<!-- Info {{{-->
> [!info]-
>
> An arbitrary file write vulnerability
> accessible via the upload method of the MediaController
> allows authenticated users to write arbitrary files
> to any location on the web server Camaleon CMS is running on
> (*depending on the permissions of the underlying filesystem*).
>
> E.g. This can lead to a delayed remote code execution
> in case an attacker is able to write a Ruby file
> into the `config/initializers/` subfolder
> of the Ruby on Rails application.
>
> This issue has been addressed in release version `2.8.2`
>
<!-- }}} -->

___
<!-- }}} -->
