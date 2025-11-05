---
id: CMS
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/CMS
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# CMS

A **Content Management System** ([CMS](https://en.wikipedia.org/wiki/Content_management_system))
is a software used to manage the creation and modification of digital contents
(*e.g., websites*).

> [!tip]- Common CMS
>
> Most common CMS
>
> - [WordPress](https://wordpress.com/)
> - [Joomla](https://www.joomla.org/)
> - [Drupal](https://new.drupal.org/)
> - [Shopify](https://www.shopify.com)
> - [Magento](https://magento-opensource.com/)
> - [Typo3](https://typo3.org/)

___

<!-- Enumeration {{{-->
## Enumeration

Identify technologies on websites

<!-- Website {{{-->
### Website

Check the website for

- Credits at the bottom or corner of pages
- Comments and metadata
- Stack traces and verbose error messages

<!-- }}} -->

<!-- Paths {{{-->
### Paths

Identify telltale file paths or directory names

> [!tip]-
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

<!-- Online Tools {{{-->
### Online Tools


- [Whatcms](https://whatcms.org/)

<!-- }}} -->

<!-- Browser Extension {{{-->
### Browser Extension

Wappalyzer constantly tries to fingerprint technologies
on every new visited URL

- [Wappalyzer](https://www.wappalyzer.com/)
- [Wappalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)
  (*Firefox Add-on*)

> [!warning]
>
> Wappalyzer may not detect a CMS initially.
>
> The site may need to be refreshed or another page should be visited.

<!-- }}} -->

<!-- Tag {{{-->
### Tag

Get the tag (*HTML metadata element*) used by default in popular CMS

```sh
curl -s http://<target>/index.php | grep '<meta name="generator"'
```

<!-- }}} -->

<!-- Scan {{{-->
### Scan

Enumerate using automated scanner

<!-- WPScan {{{-->
#### WPScan

[WPScan](https://github.com/wpscanteam/wpscan)
WordPress security scanner

Simple scan (*no exploitation*)

```sh
wpscan --url <target>
```

Enumerate users

```sh
wpscan --url <target> --enumerate u
```

Enumerate a range of users

```sh
wpscan --url <target> --enumerate u1-100
```

Bruteforce a user

```sh
wpscan --url <target> --username <username> --passwords "<wordlist.txt>"
```

Enumerate and bruteforce users

```sh
wpscan --url <target> --enumerate u --passwords "<wordlist.txt>"
```
<!-- }}} -->

<!-- Droopescan {{{-->
#### Droopescan

[[Droopescan]] supports Drupal, SilverStripe and WordPress
(*and partially supports Joomla and Moodle*)

CMS identification

```sh
droopescan scan -u <target_url>
```

Basic scan (known CMS)

```sh
droopescan scan <cms_name> -u <target_url>
```
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->
