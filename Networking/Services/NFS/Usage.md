---
id: Usage
aliases:
  - Network File System
tags:
  - Networking/Services/NFS/Usage
links: "[[Services]]"
---

# Usage

## ExportFS

Share the directory `/mnt/nfs` to the subnet `101.129.14.0/24`.

```sh
sudo echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
sudo systemctl restart nfs-kernel-server 
sudo exportfs
```

All hosts on this subnet well be ablet to mount to this NFS share.
