---
id: Btrfs
aliases: []
tags:
  - Linux/General/Filesystem/Btrfs
---

# BTRFS

From the [Btrfs Documentation](https://btrfs.readthedocs.io/en/latest/#):

> [!quote]
>
>[Btrfs](https://wiki.archlinux.org/title/Btrfs) is a modern copy on write (COW)
>file system for Linux aimed at implementing advanced features while also
>focusing on fault tolerance, repair and easy administration

<!-- Usage {{{-->
## Usage

[List snapshots (subvolumes)](https://wiki.archlinux.org/title/btrfs#Listing_subvolumes)

```sh
sudo btrfs subvolume list -p <path>
```

> [!example]-
>
>```sh
>sudo btrfs subvolume list -p /home
>```

[Delete snapshot (subvolume)](https://wiki.archlinux.org/title/snapper#Delete_a_snapshot)

```sh
sudo btrfs subvolume delete </path/to/subvolume>
```

> [!example]-
>
>```sh
>sudo btrfs subvolume delete /home/.snapshots/1/snapshot
>```

Filesystem usage
```sh
sudo btrfs filesystem usage /
```
<!-- }}} -->

<!-- Snapper {{{-->
## Snapper

[Snapper](https://wiki.archlinux.org/title/Snapper) is a tool that helps with
managing snapshots of **Btrfs** subvolumes

### Managing Snapshots

[List configurations](https://wiki.archlinux.org/title/snapper#List_configurations) that have been created

```sh
sudo snapper list-configs
```

[List snapshots](https://wiki.archlinux.org/title/snapper#List_snapshots) taken
for a given configuration *config*

```sh
sudo snapper -c <config> list
```

> [!example]-
>
>```sh
>sudo snapper -c home list
>```

Set config

```sh
sudo snapper -c home set-config <configuration>
```

> [!example]-
>
>```sh
>sudo snapper -c home set-config "TIMELINE_CREATE=no"
>```
<!-- }}} -->

<!-- Mount {{{-->
# Mount

## Mount Specific Subvolume

Mount a specific subvolume

```sh
sudo mount -o subvol=@<subvolume> /dev/mapper/external /mnt/ext
```

> [!example]-
>
> Mount the subvolume `home`
>
>```sh
>sudo mount -o subvol=@home /dev/mapper/external /mnt/ext
>```
<!-- }}} -->
