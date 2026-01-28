---
id: Error Pages
aliases: []
tags:
  - Webapp/Enumeration/Fingerprinting/Error-Pages
links: "[[Webapp]]"
---

# Error Page

Error messages can leak information regarding the technologies used

> [!todo]
> [0xdf - 404 Cheatsheet](https://0xdf.gitlab.io/cheatsheets/404#)
___

<!-- Get Error Page {{{-->
## Get Error Page

Retrieve the error page (*status code `404`*)

```sh
curl -X GET http://$target/404page
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> curl -X GET http://example.com/404page
> ```
<!-- }}} -->

___
<!-- }}} -->
