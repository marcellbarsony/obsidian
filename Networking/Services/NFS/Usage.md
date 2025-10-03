---
id: Usage
aliases:
  - Network File System
tags:
  - Networking/Services/NFS/Usage
links: "[[Services]]"
---

# Usage

<!-- List Contents {{{-->
## List Contents

List Contents with Usernames & Group Names

```sh
ls -l mnt/nfs/
```

List Contents with UIDs & GUIDs

```sh
ls -n mnt/nfs/
```
<!-- }}} -->

<!-- ExportFS {{{-->
## ExportFS

Share the directory `/mnt/nfs` to the subnet `101.129.14.0/24`.

```sh
sudo echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
sudo systemctl restart nfs-kernel-server 
sudo exportfs
```

All hosts on this subnet well be able to mount to this NFS share.
<!-- }}} -->
