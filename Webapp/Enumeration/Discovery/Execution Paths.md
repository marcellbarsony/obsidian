---
id: Execution Paths
aliases: []
tags:
  - Webapp/Enumeration/Discovery/Execution_Paths
links: "[[Webapp/Enumeration/Discovery]]"
---

# Execution Paths

Check if directory listing is enabled and search for execution paths

___

<!-- Page Enumeration {{{-->
## Page Enumeration

Enumerate common pages, files and their extensions

<!-- General {{{-->
### General

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> General
>
> - [[Dirbuster#Pages|Dirbuster]]
> - [[SecLists#Pages|SecLists]]
>
<!-- }}} -->

[[Ffuf]] - General enumeration (*Page/File/Directory*)

```sh
ffuf -w <wordlist>:FUZZ -u http://$target[:port]/FUZZ
```

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Extensions {{{-->
### Extensions

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> Web Extensions
>
> - [[SecLists#File Extensions|SecLists]]
>
> General
>
> - [[Dirbuster#Pages|Dirbuster]]
> - [[SecLists#Pages|SecLists]]
>
<!-- }}} -->

[[Ffuf]] - Enumerate web extensions

1. Enumerate `index` page extensions

<!-- Info {{{-->
> [!info]-
>
> Assume `index.<ext>`is the default page on most websites
>
<!-- }}} -->

```sh
ffuf -w <wordlist>:FUZZ -u http://$target[:port]/indexFUZZ
```

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -u http://$target/FUZZ/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions-big.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-extensions-lowercase.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-extensions-lowercase.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-extensions-lowercase.txt:FUZZ
> ```
<!-- }}} -->

2. Enumerate pages for found extension(s)

```sh
ffuf -w <wordlist>:FUZZ -u http://$target[:port]/FUZZ -w <wordlist> -e .php,.txt
```

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ -e .php.txt
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ -e .php,.txt
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt:FUZZ -e .php,.txt
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ -e .php,.txt
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ -e .php,.txt
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Context {{{-->
### Context

Enumerate based on context

<!-- Example {{{-->
> [!example]-
>
> ```sh
> one-app.api.target.com
> ```
>
> Enumerate based on keywords in URL
> (*e.g., `api`, `app`, `one`*)
>
> ```sh
> one-app.api.target.com/api/FUZZ
> ```
> ```sh
> one-app.api.target.com/app/FUZZ
> ```
> ```sh
> one-app.api.target.com/one/FUZZ
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- }}} -->

<!-- Directory Enumeration {{{-->
## Directory Enumeration

Enumerate common directories

- Navigate directory structure in the browser
- Conduct [[Gobuster#Recursive Directory Enumeration|Recursive Directory Enumeration]]
- Check Framework/CMS KBs for directory structure
- Look for clues in page source code & error outputs

<!-- General {{{-->
### General

Conduct general directory enumeration

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> - [[Dirbuster#Directories|Dirbuster]]
> - [[SecLists#Web Directories|SecLists]]
<!-- }}} -->

[[Burp Suite]]

[[Dirsearch|dirsearch.py]]

```sh
dirsearch.py [-u|--url] $target [-e|--extensions] <extensions> [options]
```

[[Ffuf]]

```sh
ffuf -w <wordlist>:FUZZ -u http://$target[:<port>]/FUZZ
```

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-small.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt:FUZZ
> ```
> ```sh
> ffuf -u http://$target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/combined_directories.txt:FUZZ
> ```
>
<!-- }}} -->

[[Gobuster]]

```sh
gobuster dir -u $target -w <wordlist> -x <file_extensions>
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> gobuster dir -u http://10.10.159.137 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,php3,html
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Recursive Directory Enumeration {{{-->
### Recursive Directory Enumeration

Conduct recursive directory enumeration

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> - [[Dirbuster#Directories|Dirbuster]]
> - [[SecLists#Directories|SecLists]]
<!-- }}} -->

[[Burp Suite]]

[[Dirsearch|dirsearch.py]]

```sh

```

[[Ffuf]]

```sh
ffuf -w <wordlist>:FUZZ -u http://$target[:<port>]/content/private/plugins/FUZZ
```

[[Gobuster#Recursive Directory Enumeration|Gobuster]]

```sh
gobuster dir -u http://<host>/content/private/plugins/ -w <wordlist>
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Investigate Findings {{{-->
## Investigate Findings

Investigate discovered files and directories for secrets and clues

<!-- File Upload Directories {{{-->
### File Upload Directories

Note down the directories that may store uploaded files

<!-- Example {{{-->
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
<!-- }}} -->

<!-- }}} -->

<!-- Admin & Management Interfaces {{{-->
### Admin & Management Interfaces

Often protected or restricted, may expose controls or sensitive data

<!-- Example {{{-->
> [!example]-
>
> - `/admin`
> - `/administrator`
> - `/backend`
> - `/dashboard`
> - `/cms`
> - `/controlpanel`
> - `/panel`
<!-- }}} -->

<!-- }}} -->

<!-- Authentication & User Management {{{-->
### Authentication & User Management

Could help with login brute force, password resets, etc.

<!-- Example {{{-->
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
<!-- }}} -->

<!-- }}} -->

<!-- Configuration / Debug / Dev Tools {{{-->
### Configuration / Debug / Dev Tools

May reveal sensitive info or debug output

<!-- Example {{{-->
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
<!-- }}} -->

<!-- }}} -->

<!-- API Endpoints {{{-->
### API Endpoints

Useful for interacting with backend services:

<!-- Example {{{-->
> [!example]-
>
> - `/api`
> - `/api/v1`
> - `/graphql`
> - `/rest`
<!-- }}} -->

<!-- }}} -->

<!-- Common CMS / Framework Paths {{{-->
### Common CMS / Framework Paths

Identify common Framework and [[CMS#Paths|CMS Paths]]

<!-- Example {{{-->
> [!example]-
>
> - **WordPress**: `/wp-admin`, `/wp-content/`, `/wp-includes/`, `class-wp.php`
> - **Joomla**: `/joomla`, `/libraries/joomla/`, `/components/com_content/`
> - **Drupal**: `/drupal`, `/core/lib/Drupal/`, `/modules/`, `Drupal\Core\`
> - **Magento**: `/app/code/Magento/`, `Mage::`
> - **TYPO3**: `/typo3`, `/typo3/sysext/`, `TYPO3\CMS\`
> - **Laravel-based CMS** (*like OctoberCMS*): `/vendor`, `/vendor/laravel/`, `October\Rain\`
> - **DotNetNuke / DNN**: `DotNetNuke.` namespaces
> - **Sitecore**: `Sitecore.` namespaces or `/App_Config/Sitecore.config`
> - **Node.js**: `/node_modules`
<!-- }}} -->

<!-- }}} -->

<!-- Backup or Misconfigured Paths {{{-->
### Backup or Misconfigured Paths

Can leak source code or database dumps

<!-- Example {{{-->
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
<!-- }}} -->

<!-- }}} -->

<!-- Other Useful Targets {{{-->
### Other Useful Targets

<!-- Example {{{-->
> [!example]-
>
> - `/private`
> - `/secret`
> - `/hidden`
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
