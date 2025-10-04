## Passwordbox

## Synopsis

```sh
--paswordbox "Challenge" <height> <width>
```

**Example**

```sh
password=$(dialog --title "Passwordbox" --passwordbox "Please enter the password" 8 60 3>&1 1>&2 2>&3)
```

## Evaluation

The best option is to save the output to a variable (`$password`) and evaluate the result based on the exit status

```sh
case $? in
    0)
      echo "OK pressed."
      echo "Password entered: $password"
    ;;
    1)
      echo "CANCEL pressed."
    ;;
    255)
      echo "ESC pressed."
    ;;
    *)
      echo "Exit status $?"
      # In theory, this shouldn't happen
    ;;
esac
```
