---
id: Virtual Hosts
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Virtual_Hosts
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Virtual Hosts

[Virtual Hosting](https://en.wikipedia.org/wiki/Virtual_hosting)
is a method for hosting multiple domain names on a single server
(*same IP address*).

> [!tip]-
>
> If a **Virtual Host** doesn't have a DNS record, it can be accessed
> by modifying the [[DNS/General#Hosts File|hosts file]].

<!-- Discovery {{{-->
## Discovery

Virtual Host discovery with [[Gobuster#Brute Forcing|Gobuster]]

```sh
gobuster vhost -u http://<target> -w <wordlist.txt> --append-domain
```

> [!tip]- Wordlists
>
> [SecLists/Discovery/DNS](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS)
>
> ```sh
> /usr/share/seclists/Discovery/DNS/namelist.txt
> ```
> ```sh
> /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
> ```

> [!warning]
>
> Virtual Host Discovery can generate significant traffic
> and might be detected by intrusion detection systems (*IDS*)
> or web application firewalls (*WAF*)

___
<!-- }}} -->

<!-- Enumeration {{{-->
## Enumeration

### Banner Grabbing

Show response headers

```sh
curl -s -D - -o /dev/null -H "Host: <target_vhost>" http://<target_ip>/
```

> [!example]-
>
> ```sh
> curl -s -D - -o /dev/null -H "Host: app.inlanefreight.local" http://10.129.222.107/
> ```

Show response headers and body

```sh
curl -v -H "Host: <target_vhost>" http://<target_ip>/
```

> [!example]-
>
> ```sh
> curl -v -H "Host: app.inlanefreight.local" http://10.129.222.107/
> ```

Raw TCP

```sh
printf 'GET / HTTP/1.1\r\nHost: app.inlanefreight.local\r\nConnection: close\r\n\r\n' | nc 10.129.222.107 80
```

___
<!-- }}} -->
