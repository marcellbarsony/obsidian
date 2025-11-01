---
id: Execution Paths
aliases: []
tags: []
---

# Execution Paths

Check if directory listing is enabled and search for execution paths

___

<!-- Directory Structure {{{-->
## Directory Structure

- Navigate directory structure in the browser

- Conduct [[Gobuster#Recursive Directory Enumeration|Recursive Directory Enumeration]]

- Check Framework/CMS KBs for directory structure

- Look for clues in page source code & error outputs

### Directory Enumeration

Conduct directory enumeration with

- [[Burp Suite]]
- [[Dirsearch|dirsearch.py]]
- [[Gobuster]]
- [[Ffuf]]

Conduct recursive directory enumeration with

- [[Burp Suite]]
- [[Dirsearch|dirsearch.py]]
- [[Gobuster#Recursive Directory Enumeration|Recursive Directory Enumeration]]
- [[Ffuf]]

___
<!-- }}} -->

<!-- Investigate Findings {{{-->
## Investigate Findings

Investigate discovered files and directories for secrets and clues

### File Upload Directories

Note down the directories that may store uploaded files

> [!example]-
>
> - `/assets`
> - `/content`
> - `/data`
> - `/documents`
> - `/files`
> - `/images` / `/img`
> - `/media`
> - `/plugins`
> - `/static`
> - `/storage`
> - `/tmp`
> - `/uploads`

### Admin & Management Interfaces

Often protected or restricted, may expose controls or sensitive data

> [!example]-
>
> - `/admin`
> - `/administrator`
> - `/backend`
> - `/dashboard`
> - `/cms`
> - `/controlpanel`
> - `/panel`

### Authentication & User Management

Could help with login brute force, password resets, etc.

> [!example]-
>
> - `/login`
> - `/logout`
> - `/register`
> - `/signup`
> - `/users, /user`
> - `/account`
> - `/profile`
> - `/auth`
> - `/session`

### Configuration / Debug / Dev Tools

May reveal sensitive info or debug output

> [!example]-
>
> - `/config`
> - `/configuration`
> - `/debug`
> - `/test`
> - `/dev`
> - `/env`
> - `/logs`
> - `/error`
> - `/status`

### API Endpoints

Useful for interacting with backend services:

> [!example]-
>
> - `/api`
> - `/api/v1`
> - `/graphql`
> - `/rest`

### Common CMS / Framework Paths

Identify common CMS and Framework Paths

WordPress

> [!example]-
>
> - `/wp-admin`
> - `/wp-content`
> - `/wp-includes`

Joomla

> [!example]-
>
> - `/joomla`

Drupal

> [!example]-
>
> - `/drupal`

TYPO3

> [!example]-
>
> - `/typo3`

Laravel / Composer

> [!example]-
>
> - `/vendor`

Node.js

> [!example]-
>
> - `/node_modules`

### Backup or Misconfigured Paths

Can leak source code or database dumps

> [!example]-
>
> - `/backup`
> - `/backups`
> - `/old`
> - `/test`
> - `/dev`
> - `/.git/`
> - `/.svn/`
> - `/.hg/`
> - `/db`
> - `/database`

### Other Useful Targets

> [!example]-
>
> - `/private`
> - `/secret`
> - `/hidden`
<!-- }}} -->
