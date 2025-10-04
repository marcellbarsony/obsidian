## Inputbox

## Synopsis

```sh
--inputbox "Challenge" <height> <width> <default message>
```

**Example**

```sh
value=$(dialog --title "Inputbox" --inputbox "Displayed message content" 8 40 "Make your choice" 3>&1 1>&2 2>&3)
```

## Evaluation

The best option is to save the output to a variable (`$value`) and evaluate the result based on the exit status

```sh
case $? in
    0)
      echo "OK pressed."
      echo "Value entered: $value"
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
