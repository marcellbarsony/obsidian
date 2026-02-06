---
id: HUD
aliases: []
tags:
  - Webapp/Tools/ZAP/HUD
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

<!-- HUD {{{-->
# HUD

[HUD](https://www.zaproxy.org/docs/desktop/addons/hud/)
is a completely new interface that brings information and functionality
from [[ZAP/General|ZAP]] into the browser

___


<!-- Right Frame {{{-->
## Right Frame

<!-- Alerts {{{-->
### Alerts

ZAP can raise alerts for a wide variety of potential security issues.

<!-- Example {{{-->
> [!example]-
>
> ![[hud-alerts.png]]
>
<!-- }}} -->

Inspect alert details in the Site Alerts dialog

<!-- Example {{{-->
> [!example]-
>
> ![[hud-alerts-inspect.png]]
>
<!-- }}} -->


<!-- }}} -->

<!-- Sites {{{-->
### Sites

The Sites tool allows to view the sites tree
for all of the URLs that ZAP is aware of

User-controllable HTML element attributes may lead to
potential [[XSS/General|XSS]] vulnerabilities

<!-- Example {{{-->
> [!example]-
>
> ![[hud-sites.png]]
>
<!-- }}} -->

<!-- }}} -->

<!-- Spider {{{-->
### Spider

[[Spider]] crawls the web page and follows the links
that it can find

<!-- }}} -->


___
<!-- }}} -->

<!-- Left Frame {{{-->
## Left Frame

<!-- Scope {{{-->
### Scope

The Scope Tool shows whether the page being viewed is in scope

<!-- Example {{{-->
> [!example]-
>
> ![[hud-scope.png]]
>
<!-- }}} -->

<!-- }}} -->

<!-- Fields {{{-->
### Fields

The Show/Enable Tool enables input fields disabled by developers

<!-- Example {{{-->
> [!example]-
>
> ![[hud-fields.png]]
>
<!-- }}} -->

<!-- }}} -->

<!-- Break {{{-->
### Break

The Break Tool causes the requests to be intercepted
in ZAP desktop

<!-- Example {{{-->
> [!example]-
>
> ![[hud-break.png]]
>
<!-- }}} -->

<!-- }}} -->

<!-- Comments {{{-->
### Comments

The Comments tool shows the number of HTML comments
on the current page

<!-- Example {{{-->
> [!example]-
>
> ![[hud-comments.png]]
>
<!-- }}} -->

<!-- }}} -->

<!-- Scripts {{{-->
### Scripts

ZAP Scripts can be used to create custom scans,
generate alerts, generate payloads for fuzzing
and much more

<!-- Example {{{-->
> [!example]-
>
> ![[hud-example.png]]
>
<!-- }}} -->

<!-- }}} -->

___
<!-- }}} -->

<!-- Bottom Frame {{{-->
## Bottom Frame

<!-- History {{{-->
### History

The History tab shows all of the requests
that have been made by the browser

<!-- Example {{{-->
> [!example]-
>
> ![[hud-history.png]]
>
<!-- }}} -->

<!-- }}} -->

<!-- Web Sockets {{{-->
### Web Sockets

The Web Sockets tab shows all of the WebSockets requests
that have been made by the browser

<!-- Example {{{-->
> [!example]-
>
> ![[hud-history.png]]
>
<!-- }}} -->


<!-- }}} -->
___
<!-- }}} -->
