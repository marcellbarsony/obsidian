---
id: Web Contents
aliases: []
tags:
  - Webapp/Enumeration/Web-Contents
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Web contents

___

<!-- Page Source Code {{{-->
## Page Source Code

[[cURL]] - Inspect the page soruce code for [[Secrets]]

```sh
curl http://$target | grep -iE 'user.*|pass.*|key.*|secret.*|api.*|flag.*|htb.*' 
```

[Firefox](https://www.firefox.com/en-US/) - View Page Source

```sh
Ctrl + U
```

<!-- HTML Comments {{{-->
### HTML Comments

Inspect HTML comments

- [[ZAP#HUD|ZAP HUD]]

<!-- }}} -->

<!-- JavaScript Code {{{-->
### JavaScript Code

Inspect JavaScript code for

- hidden endpoints
- credentials
- tokens
- keys

[Firefox](https://www.firefox.com/en-US/) -
View JavaScript code in the
[Debugger](https://firefox-source-docs.mozilla.org/devtools-user/debugger/)

```sh
Ctrl + Shift + I
```

```sh
Debugger
```

<!-- }}} -->

___
<!-- }}} -->

<!-- Autocompletion {{{-->
## Autocompletion

Check if `autocomplete` is disabled

1. Inspect webpage

2. Search for `autocomplete=off`

```html
autocomplete="off"
```

<!-- Info {{{-->
> [!info]-
>
> Setting `autocomplete="off"` on input fields has two effects:
>
> 1. Tells the browser not to save data inputted by the user for later
>    autocompletion
> 2. Stops the browser from caching form data in the session history
>
> [MDN - How to turn off autocompletion](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Turning_off_form_autocompletion)
>
<!-- }}} -->

<!-- Example {{{-->
> [!example]-
>
> ```html
> <input type="text" name="email" autocomplete="off">
> ```
>
> ```html
> <form autocomplete="off">
> ```
<!-- }}} -->

___
<!-- }}} -->

<!-- Hidden Fields {{{-->
## Hidden Fields

Inspect the webapp for hidden fields

- [[ZAP#HUD|ZAP HUD]]

___
<!-- }}} -->
