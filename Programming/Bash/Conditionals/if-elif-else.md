---
id: if-elif-else
aliases: []
tags: []
---

# If-Elif-Else Statement

## Syntax

```sh
if [ condition-is-true ]
then
    command N
elif [ condition-is-true ]
then
    command N
else
    command N
fi
```

> [!example]-
>
>```sh
>MY_SHELL="zsh"
>
>if [ "$MY_SHELL" = "bash" ]
>then
>    echo "We're using the bash shell."
>elif [ "$MY_SHELL" = "fish" ]
>then
>    echo "We're using the fish shell."
>else
>    echo "We're using some other shell."
>fi
>```
