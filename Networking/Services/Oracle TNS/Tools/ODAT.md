---
id: ODAT
aliases: []
tags:
  - Networking/Tools/ODAT
links: "[[Networking/Tools/Tools]]"
---

# ODAT

[Oracle Database Attacking Tool](https://github.com/quentinhardy/odat)
is designed to enumerate and exploit security flaws
(*e.g., SQL injection, remote code execution, privilege escalation*)
in Oracle databases

___

<!-- Install {{{-->
## Install

<!-- Repository {{{-->
### Repository

[Kali tools](https://www.kali.org/tools/odat/)

```sh
sudo apt install odat
```

<!-- }}} -->

<!-- Manual {{{-->
### Manual

Manual installation

> [!todo]
>
> Validate

1. Clone the repository to get the ODAT source code:

```sh
git clone https://github.com/quentinhardy/odat.git
```

2. Change to the directory and update wiki pages

```sh
cd odat/
```

```sh
git submodule init
```

```sh
git submodule update
```

3. Install [cx_Oracle](https://github.com/oracle/python-cx_Oracle)

```sh
sudo -s
```

```sh
source /etc/profile
```

```sh
pip3 install cx_Oracle
```

4. Install Python libraries

```sh
sudo apt-get install python3-scapy -y
```

```sh
sudo pip3 install colorlog termcolor passlib python-libnmap
```

```sh
sudo apt-get install build-essential libgmp-dev -y
```

```sh
pip3 install pycryptodome
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

Run ODAT against a target

```sh
odat all -s $target
```

> [!info]-
>
> - `all`: run all modules
> - `-s`: 

<!-- Example {{{-->
> [!example]-
>
> ```sh
> ./odat.py all -s 10.129.204.235
> ```
>
> The scan has found valid credentials :`scott`/`tiger`
>
> ```sh
> [+] Checking if target 10.129.204.235:1521 is well configured for a connection...
> [+] According to a test, the TNS listener 10.129.204.235:1521 is well configured. Continue...
>
> ...SNIP...
>
> [!] Notice: 'mdsys' account is locked, so skipping this username for password           #####################| ETA:  00:01:16 
> [!] Notice: 'oracle_ocm' account is locked, so skipping this username for password       #####################| ETA:  00:01:05 
> [!] Notice: 'outln' account is locked, so skipping this username for password           #####################| ETA:  00:00:59
> [+] Valid credentials found: scott/tiger. Continue...
>
> ...SNIP...
> ```
<!-- }}} -->

___
<!-- }}} -->
