# Exit

Every time a command is executed, it returns an
`exit status`/`exit code`/`return code`

- Ranging from `0` to `255`
- `0` means success
- Other than `0` means an error has occurred

## Syntax

**Standard user input (STDIN)**

`$?` contains the return code of the previously executed command.

```sh
ls /not/here
echo "$?"
```

The command is called on a path that doesn't exist.
After the command is executed, the return code is displayed.

`# Output: 2`

**Example**

```sh
HOST="google.com"
ping -c 1 $HOST

if [ "$?" -eq "0" ]
    then
        echo "$HOST reachable"
    else
        echo "$HOST unreachable"
fi
```

**Example 2**

```sh
HOST="google.com"
ping -c 1 $HOST

if [ "$?" -eq "0" ]
    then
        echo "$HOST reachable"
    else
        echo "$HOST unreachable"
fi
```

**Assign the error code to a variable**

```sh
HOST="google.com"
ping -c 1 $HOST
RETURN_CODE=$?

if [ "$RETURN_CODE" -ne "0" ]
    then
        echo "$HOST unreachable"
fi
```
