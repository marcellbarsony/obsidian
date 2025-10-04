# If-Else Statement

## Syntax

```sh
if [ condition-is-true ]
then
    command N
else
    command N
fi
```

Example
```sh
MY_SHELL="zsh"

if [ "$MY_SHELL" = "bash" ]
then
    echo "We're using the bash shell."
else
    echo "We're using some other shell."
fi
```
