---
id: Spider
aliases: []
tags:
  - Webapp/Tools/ZAP/Spider
links: "[[Webapp/Enumeration/Tools/Tools|Tools]]"
---

# Spider

[Spider](https://www.zaproxy.org/docs/desktop/addons/spider/)
is a tool that is used to automatically discover new resources (*URLs*)
on a particular Site

___

1. Open the [Spider dialog](https://www.zaproxy.org/docs/desktop/addons/spider/dialog/)

```sh
CTRL + ALT + S
```

```sh
Tools > Spider
```

```sh
CONTEXT > Attack > Spider
```

<!-- Example {{{-->
> [!example]-
>
> ![[spider-context.png]]
<!-- }}} -->

2. [Spider dialog]()

<!-- Example {{{-->
> [!example]-
>
> ![[spider-dialog.png]]
<!-- }}} -->

<!-- Options {{{-->
> [!info]- Options
>
> - **Recurse**: All of the nodes underneath the one selected will also be used to seed the Spider
>
> - **Spider subtree only**: The Spider will only access resources
>   that are under the starting point (*URI*)
<!-- }}} -->

___
<!-- }}} -->

<!-- AJAX Spider {{{-->
# AJAX Spider

[AJAX Spider](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/)
identifies the pages of the trageted site

1. Open the [AJAX Spider dialog](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/scandialog/)

```sh
CTRL + ALT + X
```

```sh
Tools > AJAX Spider
```

```sh
CONTEXT > Attack > AJAX Spider
```

<!-- Example {{{-->
> [!example]-
>
> ![[spider-ajax.png]]
<!-- }}} -->

2. [AJAX Spider Dialog](https://www.zaproxy.org/docs/desktop/addons/ajax-spider/scandialog/)

<!-- Example {{{-->
> [!example]-
>
> ![[spider-ajax-dialog.png]]
<!-- }}} -->

<!-- Options {{{-->
> [!info]- Options
>
> - **Context**: Context to be spidered
<!-- }}} -->

___
<!-- }}} -->
