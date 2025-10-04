## Checklist

A checklist creates a multi-state switch where multiple choice is possible

## Synopsis

```sh
--checklist "Challenge" <height> <width> <list-height>
```

**Example**

```sh
options=$(dialog --title "Checklist" --checklist "Please select your options" ${options[@]} 14 60 6 --separate-output 3>&1 1>&2 2>&3)
```

The **--separate-output** switch removes the quotation mark enclosure from the output.

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

The best option is to save the output to a variable (`$options`) and evaluate the result based on the exit status

```sh
case $? in
    0)
      echo "OK pressed."
      echo "Selected options: $options"
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
