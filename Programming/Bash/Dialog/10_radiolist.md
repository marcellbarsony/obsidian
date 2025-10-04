## Radio list

A radio list creates a multi-state switch where only one item can be set

## Synopsis

```sh
--radiolist "Challenge" <height> <width> <list-height>
```

**Example**

```sh
option=$(dialog --title "Radio list" --radiolist "Please select your option" ${options[@]} 14 60 6 3>&1 1>&2 2>&3)
```

## Options

Option properties

- Value: Value of the option, transmitted in the program.
- Label: Label of the option.
- Status: The default status of the option.

```sh
"A option" "A option description" ON \
"B option" "B option description" OFF \
"C option" "C option description" ON \
"D option" "D option description" OFF \
"E option" "E option description" ON \
"F option" "F option description" OFF \
```

## Evaluation

The best option is to save the output to a variable (`$option`) and evaluate the result based on the exit status

```sh
case $? in
    0)
      echo "OK pressed."
      echo "Selected option: $option"
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
