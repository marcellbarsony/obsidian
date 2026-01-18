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

Enumerate common general pages

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
ffuf -w <wordlist>:FUZZ -u http://$target/FUZZ -ic
```

<!-- Info {{{-->
> [!info]-
>
> - `-c`: Colorize output
> - `-ic`: Ignore wordlist comments (*default: `false`*)
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
<!-- }}} -->

<!-- }}} -->

<!-- Extensions {{{-->
### Extensions

Enumerate web extensions

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
ffuf -w <wordlist>:FUZZ -u http://$target/indexFUZZ
```

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
> -u http://$target/FUZZ/indexFUZZ
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions-big.txt:FUZZ \
> -u http://$target/FUZZ/indexFUZZ
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-extensions-lowercase.txt:FUZZ \
> -u http://$target/FUZZ/indexFUZZ
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-extensions-lowercase.txt:FUZZ \
> -u http://$target/FUZZ/indexFUZZ
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-extensions-lowercase.txt:FUZZ \
> -u http://$target/FUZZ/indexFUZZ
> ```
<!-- }}} -->

2. Validate and examine index page response

```sh
curl -I http://$target/index.<ext>
```

<!-- Example {{{-->
> [!example]-
>
> Extensions
>
> ```sh
> curl -I http://$target/index.html
> ```
> ```sh
> curl -I http://$target/index.php
> ```
> ```sh
> curl -I http://$target/index.php7
> ```
>
> Example
>
> ```sh
> curl -I http://$target/index.php
> ```
> ```sh
> HTTP/1.1 200 OK
> Date: Sun, 18 Jan 2026 02:47:34 GMT
> Server: Apache/2.4.41 (Ubuntu)
> X-Powered-By: PHP/8.1.0-dev
> Content-Type: text/html; charset=UTF-8
> ```
>
> - The target is vulnerable to
>   [HTTP: PHP 8.1.0-dev User-Agentt Header Remote Code Execution](https://www.exploit-db.com/exploits/49933)
>
<!-- }}} -->

3. Enumerate additional pages for the found extension(s)

```sh
ffuf -w <wordlist>:FUZZ -u http://$target/FUZZ -e <ext1>,<ext2>
```

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
> -u http://$target/FUZZ \
> -e .php.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ \
> -u http://$target/FUZZ \
> -e .php.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -e .php.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -e .php.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -e .php.txt \
> -ic
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

[[Dirsearch]]

```sh
dirsearch [-u|--url] $target [-e|--extensions] <extensions> [options]
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> dirsearch -w <wordlist> -u $target
> ```
>
<!-- }}} -->

[[Ffuf]]

```sh
ffuf -w <wordlist>:FUZZ -u http://$target/FUZZ -c -ic
```

<!-- Info {{{-->
> [!info]-
>
> - `-c`: Colorize output
> - `-ic`: Ignore wordlist comments (*default: `false`*)
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Wordlists
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-small.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/combined_directories.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
>
> Example
>
> ```sh
> ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
> -u http://faculty.academy.htb:30511/FUZZ \
> -recursion -recursion-depth 1 \
> -e .php,.php,.php7 \
> -fs 287 \
> -mr "You don't have access!" \
> -t 100
> ```
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

[[Dirsearch]]

```sh

```

[[Ffuf]]

```sh
ffuf -w <wordlist>:FUZZ \
-u http://$target/FUZZ \
-recursion -recursion-depth 1 \
-ic
```

```sh
ffuf -w <wordlist>:FUZZ \
-u http://$target/dir1/dir2/FUZZ \
-ic
```

<!-- Info {{{-->
> [!info]-
>
> - `-ic`: Ignore wordlist comments
>   (*default: `false`*)
> - `-recursion`: Scan recursively
> - `-recursion-depth`: Maximum recursion depth
>   (*default: `false`*)
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> Wordlists - Automatic recursion
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-small.txt:FUZZ \
> -u http://$target/FUZZ \
> -recursion -recursion-depth 1 \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt:FUZZ
> -u http://$target/FUZZ \
> -recursion -recursion-depth 1 \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt:FUZZ
> -u http://$target/FUZZ \
> -recursion -recursion-depth 1 \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/combined_directories.txt:FUZZ \
> -u http://$target/FUZZ \
> -recursion -recursion-depth 1 \
> -ic
> ```
>
> Wordlists - Explicit recursion
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-small.txt:FUZZ \
> -u http://$target/<dir>/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt:FUZZ \
> -u http://$target/<dir>/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt:FUZZ \
> -u http://$target/<dir>/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/combined_directories.txt:FUZZ \
> -u http://$target/<dir>/FUZZ \
> -ic
> ```
>
> Example - Automatic recursion
>
> ```sh
> ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
> -u http://faculty.academy.htb:30511/FUZZ \
> -recursion -recursion-depth 1 \
> -e .php,.php,.php7 \
> -fs 287 \
> -mr "You don't have access!" \
> -t 100
> ```
<!-- }}} -->

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
