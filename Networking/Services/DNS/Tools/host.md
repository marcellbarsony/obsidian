---
id: dig
tags:
  - Networking/Services/DNS/Tools/host
links: "[[Services]]"
---

## Host

Resolve a host name into an IP address or an IP address into a host name

```sh
host [-a] [-c Class ] [-d ] [-r ] [-t Type] [-v ] [-w ] <hostname> | <address> [Server]
```

<!-- Example {{{-->
> [!example]-
>
> Display the IP address of a host named `mephisto`
>
> ```sh
> host mephisto
> ```
> ```sh
> mephisto is 192.100.13.5, Aliases: engr, sarah
> ```
>
> Display the host whose IP address is `192.100.13.1`
>
> ```sh
> host 192.100.13.1
> ```
> ```sh
> mercutio is 192.100.13.1
> ```
>
> Display the [[Linux/General/General#NS]] record
> ```sh
> host -t ns inlanefreight.com
> ```
> ```sh
> ;; communications error to ::1#53: connection refused
> ;; communications error to ::1#53: connection refused
> inlanefreight.com name server ns1.inlanefreight.com.
> inlanefreight.com name server ns2.inlanefreight.com. 
> ```
<!-- }}} -->

