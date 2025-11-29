---
id: Files-Directories
aliases: []
tags: []
links: "[[Linux/General/General]]"
---

# Filesystem

## Additional Drives

[lsblk](https://linux.die.net/man/8/lsblk) —
List block devices

```sh
lsblk
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> MarciPwns@htb[/htb]$ lsblk
>
> NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
> sda      8:0    0   30G  0 disk 
> ├─sda1   8:1    0   29G  0 part /
> ├─sda2   8:2    0    1K  0 part 
> └─sda5   8:5    0  975M  0 part [SWAP]
> sr0     11:0    1  848M  0 rom  
> ```
<!-- }}} -->

___
<!-- }}} -->
