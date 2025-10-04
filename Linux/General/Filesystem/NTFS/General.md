---
id: NTFS
aliases: []
tags:
  - Linux/General/Filesystem/NTFS
---

# NTFS

From [Wikipedia](https://en.wikipedia.org/wiki/NTFS):

> [!quote]
>
>**NTFS** ([New Technology File System](https://wiki.archlinux.org/title/NTFS))
>is a proprietary journaling file system developed by Microsoft. Starting with Windows NT 3.1, it is the default file system of the Windows NT family.

## Mount

### Unencrypted

Unencrypted **NTFS** drives can be mounted with
[NTFS-3G](https://github.com/tuxera/ntfs-3g), as described in the
[Arch Wiki - NTFS-3G](https://wiki.archlinux.org/title/NTFS-3G)

Two options exist when manually mounting **NTFS** partitions:

1. The traditional

```sh
sudo ntfs-3g /dev/sdX /mnt/
```

2. Calling `ntfs-3g` directly

```sh
sudo mount -t ntfs-3g /dev/sdaX /mnt/windows
```

### Encrypted

BitLocker-encrypted **NTFS** drives can be mounted with
[Dislocker](https://github.com/Aorimn/dislocker), as described in the
[Dislocker Wiki](https://github.com/Aorimn/dislocker/wiki/Mounting):

1. Decrypt the device with the BitLocker password

```sh
sudo dislocker -v -V /dev/sdX -u -- /mnt/tmp
```

2. Mount the decrypted file/volume

```sh
sudo mount -o loop,rw /mnt/tmp/dislocker-file /media/dislocker/
```
