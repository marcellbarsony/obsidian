# Man

whiptail - display dialog boxes from shell scripts [[man](https://linux.die.net/man/1/whiptail)]

## Synopsis

```sh
whiptail [ --title title ] [ --backtitle backtitle ] [ --clear ] [ --default-item string ] [ --defaultno ] [ --fb ] [ --nocancel ] [ --yes-button text ] [ --no-button text ] [ --ok-button text ] [ --cancel-button text ] [ --noitem [ ] --output-fd fd ] [ --separate-output ] [ --scrolltext ] [ --topleft ] box-options
```

## Options

--clear

> The screen will be cleared to the screen attribute on exit. This doesn't work in an xterm (and descendants) if alternate screen switching is enabled, because in that case slang writes to (and clears) an alternate screen.

--defaultno

> The dialog box will open with the cursor over the No button.

--default-item string

> Set the default item in a menu box. Normally the first item in the box is the default.

--fb

> Use full buttons. (By default, whiptail uses compact buttons).

--nocancel

> The dialog box won't have a Cancel button.

--yes-button text

> Set the text of the Yes button.

--no-buttontext

> Set the text of the No button.

--ok-button text

> Set the text of the Ok button.

--cancel-button text

> Set the text of the Cancel button.

--noitem

> The menu, checklist and radiolist widgets will display tags only, not the item strings. The menu widget still needs some items specified, but checklist and radiolist expect only tag and status.

--separate-output

> For checklist widgets, output result one line at a time, with no quoting. This facilitates parsing by another program.

--output-fd fd

> Direct output to the given file descriptor. Most whiptail scripts write to standard error, but error messages may also be written there, depending on your script.
> --title title
> Specifies a title string to be displayed at the top of the dialog box.

--backtitle backtitle

> Specifies a backtitle string to be displayed on the backdrop, at the top of the screen.

--scrolltext

> Force the display of a vertical scrollbar.

--topleft

> Put window in top-left corner.

## Box Options

--yesno text height width

> A yes/no dialog box of size height rows by width columns will be displayed. The string specified by text is displayed inside the dialog box. If this string is too long to be fit in one line, it will be automatically divided into multiple lines at appropriate places. The text string may also contain the sub-string "\n" or newline characters '\n' to control line breaking explicitly. This dialog box is useful for asking questions that require the user to answer either yes or no. The dialog box has a Yes button and a No button, in which the user can switch between by pressing the TAB key.

--msgbox text height width

> A message box is very similar to a yes/no box. The only difference between a message box and a yes/no box is that a message box has only a single OK button. You can use this dialog box to display any message you like. After reading the message, the user can press the ENTER key so that whiptail will exit and the calling shell script can continue its operation.

--infobox text height width

> An info box is basically a message box. However, in this case, whiptail will exit immediately after displaying the message to the user. The screen is not cleared when whiptail exits, so that the message will remain on the screen until the calling shell script clears it later. This is useful when you want to inform the user that some operations are carrying on that may require some time to finish.

--inputbox text height width [init]

> An input box is useful when you want to ask questions that require the user to input a string as the answer. If init is supplied it is used to initialize the input string. When inputing the string, the BACKSPACE key can be used to correct typing errors. If the input string is longer than the width of the dialog box, the input field will be scrolled. On exit, the input string will be printed on stderr.

--passwordbox text height width [init]

> A password box is similar to an input box, except the text the user enters is not displayed. This is useful when prompting for passwords or other sensitive information. Be aware that if anything is passed in "init", it will be visible in the system's process table to casual snoopers. Also, it is very confusing to the user to provide them with a default password they cannot see. For these reasons, using "init" is highly discouraged.

--textboxfile height width

> A text box lets you display the contents of a text file in a dialog box. It is like a simple text file viewer. The user can move through the file by using the UP/DOWN, PGUP/PGDN and HOME/END keys available on most keyboards. If the lines are too long to be displayed in the box, the LEFT/RIGHT keys can be used to scroll the text region horizontally. For more convenience, forward and backward searching functions are also provided.

--menu text height width menu-height [ tag item ] ...

> As its name suggests, a menu box is a dialog box that can be used to present a list of choices in the form of a menu for the user to choose. Each menu entry consists of a tag string and an item string. The tag gives the entry a name to distinguish it from the other entries in the menu. The item is a short description of the option that the entry represents. The user can move between the menu entries by pressing the UP/DOWN keys, the first letter of the tag as a hot-key. There are menu-height entries displayed in the menu at one time, but the menu will be scrolled if there are more entries than that. When whiptail exits, the tag of the chosen menu entry will be printed on stderr.

--checklist text height width list-height [ tag item status ] ...

> A checklist box is similar to a menu box in that there are multiple entries presented in the form of a menu. You can select and deselect items using the SPACE key. The initial on/off state of each entry is specified by status. On exit, a list of the tag strings of those entries that are turned on will be printed on stderr.

--radiolist text height width list-height [ tag item status ] ...

> A radiolist box is similar to a menu box. The only difference is that you can indicate which entry is currently selected, by setting its status to on.

--gauge text height width percent

> A gauge box displays a meter along the bottom of the box. The meter indicates a percentage. New percentages are read from standard input, one integer per line. The meter is updated to reflect each new percentage. If stdin is XXX, then subsequent lines up to another XXX are used for a new prompt. The gauge exits when EOF is reached on stdin.

## Resources

[xmodulo](https://www.xmodulo.com/create-dialog-boxes-interactive-shell-script.html)

[wikibooks](https://en.wikibooks.org/wiki/Bash_Shell_Scripting/Whiptail)

[redhat](https://www.redhat.com/sysadmin/use-whiptail)

[linuxportal](https://en.linuxportal.info/tutorials/programming/shell-scripts/managing-dialog-boxes/getting-to-know-the-whiptail-dialog-program)

[gijs-de-jong.nl](https://gijs-de-jong.nl/posts/pretty-dialog-boxes-for-your-shell-scripts-using-whiptail/)

[saveriomiroddi.github.io](https://saveriomiroddi.github.io/Shell-scripting-adventures-part-3/)

[linuxfordevices.com](https://www.linuxfordevices.com/tutorials/shell-script/interactive-shell-scripts-whiptail)
