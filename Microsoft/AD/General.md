---
id: Active Directory
aliases: "AD"
tags:
  - Microsoft
  - Active-Directory
links: "[[Microsoft]]"
---

# Active Directory

**Active Directory**
(*[AD](https://en.wikipedia.org/wiki/Active_Directory)*)
is a [directory service](https://en.wikipedia.org/wiki/Directory_service)
for Windows domain network environments

**Active Directory** is a distributed hierarchical structure
that allows for centralized management of an organization's resources
(*e.g., Users, Computers, Groups, Network devices and File shares,
Group Policies, Servers and Workstations, Trusts, etc.*)

**Active Directory** provides authentication and authorization
functions within a Windows domain environment

___

<!-- Active Directory Services {{{-->
## Active Directory Services

### Certificate Services

**Active Directory Certificate Services**
(*[AD CS](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)*)

> [!todo]

### Domain Services

**Active Directory Domain Services** (*[AD DS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)*)
allow organizations to store directory data
(*e.g., usernames, passwords*)

> [!todo]

### Federation Services

**Active Directory Federation Services**
(*[AD FS](https://en.wikipedia.org/wiki/Active_Directory_Federation_Services)*)
provide [single sign-on](https://en.wikipedia.org/wiki/Single_sign-on)
access to systems and applications located across organizational boundaries
using a [claims-based](https://en.wikipedia.org/wiki/Claims-based_identity)
access-control organization model

### Lightweight Directory Services

**Active Directory Lightweight Directory Services**
(*[AD LDS](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/adam/what-is-active-directory-lightweight-directory-services)*)

> [!todo]

___
<!-- }}} -->

<!-- Structure {{{-->
## Structure

**Active Directory** is arranged in a hierarchical tree structure

<!-- Example {{{-->
> [!example]-
>
> - **Root Domain** (*Forest*):
>   Root domain that contains subdomains
>  (*e.g., `INLANEFREIGHT.LOCAL`*)
> - **Forests**: `INLANEFREIGHT.LOCAL`, `FREIGHTLOGISTICS.LOCAL`
> - **Subdomain**:
>  (*e.g., `ADMIN.INLANEFREIGHT.LOCAL`,
>  `CORP.INLANEFREIGHT.LOCAL`
>  `DEV.INLANEFREIGHT.LOCAL`*)
> - **Organizational Units** (*OU*):
>  (*e.g., [[Domain Controller]], Users, Computers*)
>
> ```
> INLANEFREIGHT.LOCAL/
> ├── ADMIN.INLANEFREIGHT.LOCAL
> │   ├── GPOs
> │   └── OU
> │       └── EMPLOYEES
> │           ├── COMPUTERS
> │           │   └── FILE01
> │           ├── GROUPS
> │           │   └── HQ Staff
> │           └── USERS
> │               └── barbara.jones
> ├── CORP.INLANEFREIGHT.LOCAL
> └── DEV.INLANEFREIGHT.LOCAL
> ```
<!-- }}} -->

![[ad-forests-domains.png]]

### Objects

#### Resources

#### Security Principals

[Security Principals](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-principals)
are anything that the operating system can authenticate,
including users, computer accounts, or even threads/processes
that run in the context of a user or computer account

### Domains

#### Forest

A **Forest** is a collection of Active Directory domains

##### Domain

##### Organizational Units

###### Shadow Groups

___
<!-- }}} -->
