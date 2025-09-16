---
id: Execution Paths
aliases: []
tags: []
---

# Execution Paths

Check if directory listing is enabled and search for execution paths

## Directory Enumeration

Conduct directory enumeration with `Burp Suite`, `dirsearch.py`, `gobuster` and
`Fuff`

### Recursive Directory Enumeration

Conduct recursive directory enumeration with `Burp Suite`, `dirsearch.py`,
`gobuster` and `Fuff`

## Directory Structure

- Navigate directory structure in the browser

- Conduct [[gobuster#Recursive Directory Enumeration|Recursive Directory Enumeration]]

- Check Framework/CMS KBs for directory structure

- Look for clues in page source code & error outputs

<!-- Investigate Findings {{{ -->
## Investigate Findings

Investigate discovered files and directories for secrets and clues

### File Upload Directories

Note down the directories that may store uploaded files:

- `/assets`
- `/content`
- `/data`
- `/documents`
- `/files`
- `/images` / `/img`
- `/media`
- `/plugins`
- `/static`
- `/storage`
- `/tmp`
- `/uploads`

### Admin & Management Interfaces
Often protected or restricted, may expose controls or sensitive data:

- `/admin`
- `/administrator`
- `/backend`
- `/dashboard`
- `/cms`
- `/controlpanel`
- `/panel`

### Authentication & User Management

Could help with login brute force, password resets, etc.:

- `/login`
- `/logout`
- `/register`
- `/signup`
- `/users, /user`
- `/account`
- `/profile`
- `/auth`
- `/session`

### Configuration / Debug / Dev Tools

May reveal sensitive info or debug output:

- `/config`
- `/configuration`
- `/debug`
- `/test`
- `/dev`
- `/env`
- `/logs`
- `/error`
- `/status`

### API Endpoints

Useful for interacting with backend services:

- `/api`
- `/api/v1`
- `/graphql`
- `/rest`

### Common CMS / Framework Paths

Identify common CMS and Framework Paths

WordPress

- `/wp-admin`
- `/wp-content`
- `/wp-includes`

Joomla

- `/joomla`

Drupal

- `/drupal`

TYPO3

- `/typo3`

Laravel / Composer:

- `/vendor`

Node.js:

- `/node_modules`

### Backup or Misconfigured Paths

Can leak source code or database dumps:

- `/backup`
- `/backups`
- `/old`
- `/test`
- `/dev`
- `/.git/`
- `/.svn/`
- `/.hg/`
- `/db`
- `/database`

### Other Useful Targets

- `/private`
- `/secret`
- `/hidden`
<!-- }}} -->
