---
id: if
aliases: []
tags: []
---

# If Statement

## Syntax

```sh
if [ condition-is-true ]
then
    command 1
    command 2
    command N
fi
```

> [!example]-
>
>```sh
>MY_SHELL="bash"
>
>if [ "$MY_SHELL" = "bash" ]
>then
>    echo "We're using the bash shell."
>fi
>```
