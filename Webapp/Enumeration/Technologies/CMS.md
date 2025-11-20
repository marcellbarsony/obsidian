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

___

<!-- Enumeration {{{-->
## Enumeration

Identify technologies on websites

<!-- Common CMS {{{-->
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
<!-- }}} -->


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

<!-- Common Paths {{{-->
> [!tip]- Common Paths
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

<!-- Online Tools {{{-->
### Online Tools

- [Whatcms](https://whatcms.org/) — What CMS Is This Site Using?

<!-- }}} -->

<!-- Browser Extension {{{-->
### Browser Extension

Wappalyzer constantly tries to fingerprint technologies
on every new visited URL

- [Wappalyzer](https://www.wappalyzer.com/) — Identify technologies on websites
- [Wappalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)
  (*Firefox Add-on*)

> [!warning]
>
> Wappalyzer may not detect a CMS initially.
>
> The site may need to be refreshed or another page should be visited.

<!-- }}} -->

<!-- HTML Tag {{{-->
### HTML Tag

Get the tag (*HTML metadata element*) used by default in popular CMS

```sh
curl -s http://<target>/index.php | grep '<meta name="generator"'
```

<!-- }}} -->

<!-- Scan {{{-->
### Scan

Enumerate using automated scanner

- [[Nikto]]
- [[WhatWeb]]
- [[Droopescan]]
- [[WPScan]]

<!-- }}} -->

___
<!-- }}} -->
