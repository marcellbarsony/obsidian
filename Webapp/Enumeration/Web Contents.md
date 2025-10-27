---
id: Web Contents
aliases: []
tags:
  - Webapp/Enumeration/Web-Contents
links: "[[Webapp/Enumeration/Enumeration|Enumeration]]"
---

# Web contents

___

<!-- Autocompletion {{{-->
## Autocompletion

Check if `autocomplete` is disabled

```html
autocomplete="off"
```

> [!info]-
>
> Setting `autocomplete="off"` on input fields has two effects:
>
> 1. It tells the browser not to save data inputted by the user for later
>    autocompletion
> 2. It stops the browser from caching form data in the session history
>
> [MDN - How to turn off autocompletion](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Turning_off_form_autocompletion)

___
<!-- }}} -->

<!-- Page Source Code {{{-->
## Page Source Code

Inspect the page soruce code (`Ctrl + U`) for sensitive information:

- IDs
- API Keys
- Usernames (`admin`)
- Passwords
- Other useful information

___
<!-- }}} -->

<!-- JavaScript Code {{{-->
### JavaScript Code

Inspect JavaScript code for

- hidden endpoints
- credentials
- tokens
- keys

___
<!-- }}} -->
