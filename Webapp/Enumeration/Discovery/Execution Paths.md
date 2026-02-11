---
id: Execution Paths
aliases: []
tags:
  - Webapp/Enumeration/Discovery/Execution_Paths
links: "[[Webapp/Enumeration/Discovery]]"
---

# Execution Paths

Check if directory listing is enabled and fuzz execution paths

___

<!-- Extension Enumeration {{{-->
## Extension Enumeration

Enumerate web extensions

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> Web Extensions
>
> - [[SecLists#File Extensions|SecLists]]
>
> Web Pages
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
> -u http://$target/FUZZ/indexFUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions-big.txt:FUZZ \
> -u http://$target/FUZZ/indexFUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-extensions-lowercase.txt:FUZZ \
> -u http://$target/FUZZ/indexFUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-extensions-lowercase.txt:FUZZ \
> -u http://$target/FUZZ/indexFUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-extensions-lowercase.txt:FUZZ \
> -u http://$target/FUZZ/indexFUZZ \
> -ic
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
> -e .php,.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ \
> -u http://$target/FUZZ \
> -e .php,.txt \
> -ic
> ```
>
> Raft Files (*lowercase*)
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -e .php,.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -e .php,.txt \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -e .php,.txt \
> -ic
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Page Enumeration {{{-->
## Page Enumeration

Enumerate common pages, files and their extensions

<!-- General {{{-->
### General

Enumerate common general pages

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> - [[Dirbuster#Pages|Dirbuster]]
> - [[SecLists#Pages|SecLists]]
>
<!-- }}} -->

[[Ffuf]] - General enumeration (*Page/File/Directory*)

```sh
ffuf -w <wordlist>:FUZZ -u http://<domain>/FUZZ
```

<!-- Example {{{-->
> [!example]-
>
> **Wordlists**
>
> Common
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
>
> Big
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
>
> Raft Files (*Lowercase*)
>
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
>
> Raft Files
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
>
> <!-- Info {{{-->
> > [!info]-
> >
> > - `-c`: Colorize output
> > - `-ic`: Ignore wordlist comments (*default: `false`*)
> >
> <!-- }}} -->
>
<!-- }}} -->

[[Gobuster]]

```sh
gobuster dir [flags] -u <target> -w <wordlist>
```

<!-- Example {{{-->
> [!example]-
>
> Common
>
> ```sh
> gobuster dir -u http://$target \
> -w /usr/share/seclists/Discovery/Web-Content/common.txt
> ```
>
> Big
>
> ```sh
> gobuster dir -u http://$target \
> -w /usr/share/seclists/Discovery/Web-Content/big.txt
> ```
>
> Raft Files (*Lowercase*)
>
> ```sh
> gobuster dir -u http://$target \
> -w /usr/share/seclists/Discovery/Web-Content/raft-small-files-lowercase.txt
> ```
> ```sh
> gobuster dir -u http://$target \
> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt
> ```
> ```sh
> gobuster dir -u http://$target \
> -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt
> ```
>
> Raft Files
>
> ```sh
> gobuster dir -u http://$target \
> -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt
> ```
> ```sh
> gobuster dir -u http://$target \
> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
> ```
> ```sh
> gobuster dir -u http://$target \
> -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt
> ```
>
> <!-- Info {{{-->
> > [!info]-
> >
> > - `-c`: Colorize output
> > - `-ic`: Ignore wordlist comments (*default: `false`*)
> >
> <!-- }}} -->
>
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
>
<!-- }}} -->

[[Burp Suite]]

[[Ffuf]]

```sh
ffuf -w <wordlist>:FUZZ -u http://$target/FUZZ
```

<!-- Example {{{-->
> [!example]-
>
> **Wordlists**
>
> DirBuster Directories List (*Lowercase*)
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
>
> DirBuster Directories Lists
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
>
> Raft Directory Lists (*Lowercase*)
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
>
> Raft Directory Lists
>
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
> ```sh
> ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:FUZZ \
> -u http://$target/FUZZ \
> -ic
> ```
>
> <!-- Info {{{-->
> > [!info]-
> >
> > - `-c`: Colorize output
> > - `-ic`: Ignore wordlist comments (*default: `false`*)
> >
> <!-- }}} -->
>
> **Example**
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
>
<!-- }}} -->

[[Gobuster]]

```sh
gobuster dir -u $target -w <wordlist> -x <file_extensions>
```

<!-- Example {{{-->
> [!example]-
>
> **Wordlists**
>
> DirBuster Directories List (*Lowercase*)
>
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-small.txt
> ```
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
> ```
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-big.txt
> ```
>
> DirBuster Directories Lists
>
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt
> ```
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
> ```
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
> ```
>
> Raft Directory Lists (*Lowercase*)
>
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
> ```
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
> ```
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
> ```
>
> Raft Directory Lists
>
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
> ```
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
> ```
> ```sh
> gobuster dir \
> -u http://$target/FUZZ \
> -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
> ```
>
> **Example**
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
>
<!-- }}} -->

<!-- }}} -->

<!-- Recursive {{{-->
### Recursive

Conduct recursive directory enumeration

<!-- Wordlists {{{-->
> [!tip]- Wordlists
>
> - [[Dirbuster#Directories|Dirbuster]]
> - [[SecLists#Directories|SecLists]]
<!-- }}} -->

[[Burp Suite]]

[[Ffuf]] - Automatic/Explicit recursion

```sh
ffuf -w <wordlist>:FUZZ -u http://$target/FUZZ -recursion -recursion-depth 1
```

```sh
ffuf -w <wordlist>:FUZZ -u http://$target/dir1/dir2/FUZZ
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

<!-- Web Shell Enumeration {{{-->
## Web Shell Enumeration

Enumerate web shells

<!-- Tip {{{-->
> [!tip]- Wordlists
>
> [[Wordlists/Custom/web-shells.txt]]
>
<!-- }}} -->

[[Ffuf]] - General webshell enumeration

```sh
ffuf -w <wordlist>:FUZZ -u http://<domain>/FUZZ
```

<!-- Example {{{-->
> [!example]-
>
> **Wordlists**
>
> ```sh
> ffuf -w web-shells.txt \
> -u http://$target/FUZZ \
> -ic
>
<!-- }}} -->

___
<!-- }}} -->

<!-- Investigate Findings {{{-->
# Investigate Findings

Investigate discovered files and directories for [[Secrets]]
and clues

**Admin & Management Interfaces**

Often protected or restricted,
may expose controls or sensitive data

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

**API Endpoints**

Useful for interacting with backend services:

<!-- Example {{{-->
> [!example]-
>
> - `/api`
> - `/api/v1`
> - `/graphql`
> - `/rest`
<!-- }}} -->

**Authentication & User Management**

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

**Backup or Misconfigured Paths**

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

**Common CMS / Framework Paths**

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

**Configuration / Debug / Dev Tools**

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

**File Upload Directories**

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

**Other Useful Targets**

<!-- Example {{{-->
> [!example]-
>
> - `/private`
> - `/secret`
> - `/hidden`
<!-- }}} -->

___
<!-- }}} -->
