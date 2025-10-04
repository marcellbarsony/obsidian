## Textbox

## Synopsis

```sh
--textbox <file> <height> <width>
```

**Example**

```sh
dialog --title "Textbox" --textbox ./file.txt 16 60 --scrolltext
```

**--scrolltext** allows to scroll the content of the textbox with the arrow keys.

## Evaluation

We can evaluate the result based on the exit code (OK = 0, ESC = 255)

```sh
if [[ $? == 0 ]] ; then
    echo "OK pressed."
else
    echo "ESC pressed."
fi
```
