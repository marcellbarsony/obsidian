---
id: Enumeration
aliases:
  - Network File System
tags:
  - Networking/Services/NFS/Enumeration
links: "[[Services]]"
---

# Enumeration

## Nmap

Enumerating TCP ports `111` and `2049` are essential

```sh
sudo nmap -sC -sV <target_ip> -p111,2049
```

The `rpcinfo` NSE script retrieves a list of running RPC services.
This checks whether the target share is connected to the network on all required
ports.

```sh
sudo nmap --script nfs* <target_ip> -sV -p111,2049
```

## Show NFS Shares

Once NFS services are discovered, they can be mounted to the local machine.

```sh
showmount -e <target_ip>
```

## Mount NFS Shares

```sh
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .
```

## List Contents

List Contents with Usernames & Group Names

```sh
ls -l mnt/nfs/
```

List Contents with UIDs & GUIDs

```sh
ls -n mnt/nfs/
```

## Unmounting

```sh
sudo umount ./target-NFS
```
