---
id: Droopescan
aliases: []
tags:
  - Webapp/Enumeration/Tools/Droopescan
links: "[[Webapp/Enumeration/Enumeration/Tools|Tools]]"
---

# Droopescan

[Droopescan](https://github.com/SamJoan/droopescan)
is a plugin-based scanner that aids security researchers
in identifying issues with several CMSs,
mainly Drupal & Silverstripe

Supported CMS are:

- SilverStripe
- Wordpress
- Drupal

Partial functionality for:

- Joomla (*version enumeration and interesting URLs only*)
- Moodle (*plugin & theme very limited*)

___

<!-- Install {{{-->
## Install

> [!todo]

[pipx]()

```sh
pipx install droopescan
```

[pip]()

```sh
apt-get install python-pip
```

```sh
pip install droopescan
```
___
<!-- }}} -->

<!-- Usage {{{-->
## Usage

CMS identification

```sh
droopescan scan -u <target_url>
```

Basic scan (known CMS)

```sh
droopescan scan <cms_name> -u <target_url>
```
___
<!-- }}} -->
