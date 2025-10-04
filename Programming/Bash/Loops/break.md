# Break

The break statement exits the loop but the script will continue to run.<br>
The break statement can be used by other types of loops as well.

## Example

```sh
while true
do
  read -p "1: Show disk usage. 2: Show uptime. " CHOICE
  case "$CHOICE" in
    1)
      df -h
      ;;
    2)
      uptime
      ;;
    *)
      break
      ;;
  esac
done
```

If everything else than `1` and `2` is entered by the user, then the break
statement is executed and ends the while loops.
