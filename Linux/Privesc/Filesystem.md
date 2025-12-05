---
id: Filesystem
aliases: []
tags: []
links: "[[Linux/Privesc/Filesystem]]"
---

# Filesystem

___

<!-- Filesystems {{{-->
## Filesystems

[df](https://linux.die.net/man/1/df) —
List mounted filesystems

```sh
df -h
```

List unmounted filesystems

```sh
cat /etc/fstab | grep -v "#" | column -t
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> cat /etc/fstab | grep -v "#" | column -t
> ```
> ```sh
> UUID=5bf16727-fcdf-4205-906c-0620aa4a058f  /          ext4  errors=remount-ro  0  1
> UUID=BE56-AAE0                             /boot/efi  vfat  umask=0077         0  1
> /swapfile                                  none       swap  sw                 0  0
> ```
<!-- }}} -->

List active mount entries

```sh
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
```

___
<!-- }}} -->

<!-- Block Devices {{{-->
## Block Devices

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

List mounted block devices

```sh
ls /dev 2>/dev/null | grep -i "sd"
```

<!-- Mount {{{-->
### Mount

```sh
sudo mount /dev/sda<id> /mnt
```

<!-- }}} -->

___
<!-- }}} -->
