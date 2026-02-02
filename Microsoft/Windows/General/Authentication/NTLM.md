---
id: NTLM
aliases:
  - New Technology LAN Manager
tags:
  - Microsoft/Windows/General/Authentication/NTLM
links: "[[Microsoft/Windows/Windows]]"
---

# NTLM

**NTLM** (*[New Technology LAN Manager](https://en.wikipedia.org/wiki/NTLM)*)
is a suite of Microsoft security protocols intended to
provide authentication, integrity and confidentiality to users

**NTLM** is the successor to the authentication protocol in
Microsoft [LAN Manager](https://en.wikipedia.org/wiki/LAN_Manager)
(*LANMAN*), and is now being discounted to [[Kerberos]]

> [!warning]
>
> Despite known vulnerabilities, the various NTLM versions
> are still available on current IT systems for compatibility reasons
>
> [NTLMv2](https://en.wikipedia.org/wiki/NTLM#NTLMv2)
> is also still used for local logon, network logon for WORKGROUPS,
> some http servers and also for Single-Sign-On (SSO)

___

<!-- NTLM User Authentication {{{-->
## NTLM User Authentication

[NTLM User Authentication](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/ntlm-user-authentication)

The [NTLMv2 protocol](https://en.wikipedia.org/wiki/NTLM#NTLMv2)
uses an NT hash in a challenge/response between a server and a client

1. **NEGOTIATE**: The client machine sends a request to a server
   with the user name and other configuration information

2. **CHALLENGE**: The server generates a random number
   and sends it to the client

3. **AUTHENTICATE**: The client encrypts the random number
   using the [DES algorithm](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
   and the NT hash of the password as a key
   to prove that it knows the password

4. The server verifies the identity of the user by ensuring
   that the challenge was actually created with the correct user/password.

   The server uses the stored NT hash from its own SAM database
   or it forwards the challenge/response pair to the
   domain controller for validation

![[ntlm-authentication.png]]

___
<!-- }}} -->

<!-- Exploitation {{{-->
## Exploitation


___
<!-- }}} -->
