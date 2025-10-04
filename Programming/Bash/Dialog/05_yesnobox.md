## Yesnobox

Yes/No question box

## Synopsis

```sh
--yesno "Challenge" <height> <width>
```

**--defaultno**

Make "NO" the default value of the yes/no box.

**Example**

```sh
dialog --title "Yesnobox" --defaultno --yesno "Displayed message content" 8 40
```

## Evaluation

The best option is to evaluate the result based on the exit status.

```sh
case $? in
    0)
      echo "YES pressed."
    ;;
    1)
      echo "NO pressed."
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
