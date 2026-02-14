---
id: Services
aliases:
  - Networking Services
tags:
  - Networking/Services
links: "[[Networking]]"
---

# Network Services

<!-- The Concept Of Attacks {{{-->
## The Concept Of Attacks

The concept is based on four categories that occur for each vulnerability

- [[#Source]]: Performs the specific request to a process
- [[#Process]]: The vulnerability gets triggered
- [[#Privileges]]: Each process has a set of privileges
  with which it is executed
- [[#Destination]]: Each process has a task with a specific goal
  (*compute or forward data*)

<!-- Source {{{-->
### Source

**Source** is a source of information
used for the specific task of a [[#process]]

There are many different ways to pass information to a process

<!-- Info {{{-->
> [!info]-
>
> | Information Source | Description |
> | ------------------ | --- |
> | Code               | The executed program code results are used as a source of information. These can come from different functions of a program. |
> | Libraries          | A library is a collection of program resources, including configuration data, documentation, help data, message templates, prebuilt code and subroutines, classes, values, or type specifications. |
> | Config             | Configurations are usually static or prescribed values that determine how the process processes information. |
> | APIs               | The application programming interface (API) is mainly used as the interface of programs for retrieving or providing information. |
> | User Input         | If a program has a function that allows the user to enter specific values used to process the information accordingly, this is the manual entry of information by a person. |
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> A great example is the critical Log4j vulnerability
> (*[CVE-2021-44228](https://nvd.nist.gov/vuln/detail/cve-2021-44228)*)
> which was published at the end of 2021.
>
> [Log4j](https://logging.apache.org/log4j/2.x/index.html)
> is a framework or Library used to log application messages
> in Java and other programming languages.
> This library contains classes and functions
> that other programming languages can integrate.
>
> For this purpose, information is documented,
> similar to a logbook.
> Furthermore, the scope of the documentation
> can be configured extensively.
>
> As a result, it has become a standard
> within many open source and commercial software products.
>
> In this example, an attacker can manipulate the HTTP User-Agent header
> and insert a JNDI lookup as a command intended for the Log4j library.
>
> Accordingly, not the actual User-Agent header,
> such as Mozilla 5.0, is processed, but the JNDI lookup.
>
<!-- }}} -->

<!-- }}} -->

<!-- Process {{{-->
### Process

The **Process** is processing the information forwarded from the [[#source]]

For each task, the developer specifies how the information is processed
(*e.g., classes with different functions, calculations, loops*)

<!-- Info {{{-->
> [!info]-
>
> | Process Components | Description |
> | --- | --- |
> | PID | The Process-ID (PID) identifies the process being started or is already running. Running processes have already assigned privileges, and new ones are started accordingly. |
> | Input | This refers to the input of information that could be assigned by a user or as a result of a programmed function. |
> | Data processing | The hard-coded functions of a program dictate how the information received is processed. |
> | Variables | The variables are used as placeholders for information that different functions can further process during the task. |
> | Logging | During logging, certain events are documented and, in most cases, stored in a register or a file. This means that certain information remains in the system. |
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> The process of Log4j is to log the User-Agent as a string
> using a function and store it in the designated location.
>
> The vulnerability in this process is the misinterpretation of the string,
> which leads to the execution of a request instead of logging the events.
>
<!-- }}} -->

<!-- }}} -->

<!-- Privileges {{{-->
### Privileges

**Privileges** are present in any system that controls [[#process|processes]]
Privileges serve as a type of permission that determines
what tasks and actions can be performed on the system.

In simple terms, it can be compared to a bus ticket.
If we use a ticket intended for a particular region,
we will be able to use the bus, and otherwise, we will not.

These privileges can also be used for different means of transport,
such as planes, trains, boats, and others.

In computer systems, these privileges serve as control
and segmentation of actions for which different permissions,
controlled by the system, are needed.

Therefore, the rights are checked based on this categorization
when a process needs to fulfill its task.

If the process satisfies these privileges and conditions,
the system approves the action requested.

<!-- Info {{{-->
> [!info]-
>
> | Privileges | Description |
> | --- | --- |
> | System | These privileges are the highest privileges that can be obtained, which allow any system modification. In Windows, this type of privilege is called SYSTEM, and in Linux, it is called root. |
> | User | User privileges are permissions that have been assigned to a specific user. For security reasons, separate users are often set up for particular services during the installation of Linux distributions. |
> | Groups | Groups are a categorization of at least one user who has certain permissions to perform specific actions. |
> | Policies | Policies determine the execution of application-specific commands, which can also apply to individual or grouped users and their actions. |
> | Rules | Rules are the permissions to perform actions handled from within the applications themselves. |
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> What made the Log4j vulnerability so dangerous was the Privileges
> that the implementation brought.
>
> Logs are often considered sensitive because they can contain data
> about the service, the system itself, or even customers.
>
> Therefore, logs are usually stored in locations
> that no regular user should be able to access.
>
> Accordingly, most applications with the Log4j implementation
> were run with the privileges of an administrator.
>
> The process itself exploited the library by manipulating the User-Agent
> so that the process misinterpreted the source and led to the execution
> of user-supplied code.
>
<!-- }}} -->

<!-- }}} -->

<!-- Destination {{{-->
### Destination

Every task has at least one purpose and goal that must be fulfilled.
Logically, if any data set changes were missing
or not stored or forwarded anywhere,
the task would be generally unnecessary.

The result of such a task is either stored somewhere
or forwarded to another processing point.

Therefore we speak here of the Destination
where the changes will be made.

Such processing points can point
either to a local or remote process.

Therefore, at the local level,
local files or records may be modified
by the process or be forwarded to other local services
for further use.

However, this does not exclude the possibility
that the same process could reuse the resulting data too.

If the process is completed with the data storage or its forwarding,
the cycle leading to the task's completion is closed.

<!-- Info {{{-->
> [!info]-
>
> | Destination | Description |
> | --- | --- |
> | Local | The local area is the system's environment in which the process occurred. Therefore, the results and outcomes of a task are either processed further by a process that includes changes to data sets or storage of the data. |
> | Network | The network area is mainly a matter of forwarding the results of a process to a remote interface. This can be an IP address and its services or even entire networks. The results of such processes can also influence the route under certain circumstances. |
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> The misinterpretation of the User-Agent leads to a JNDI lookup
> which is executed as a command from the system
> with administrator privileges and queries
> a remote server controlled by the attacker,
> which in our case is the Destination in our concept of attacks.
>
> This query requests a Java class created by the attacker
> and is manipulated for its own purposes.
>
> The queried Java code inside the manipulated Java class
> gets executed in the same process,
> leading to a remote code execution (RCE) vulnerability.
>
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
