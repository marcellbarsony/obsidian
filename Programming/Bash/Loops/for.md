# For Loop

## Syntax

```sh
for VARIABLE_NAME in ITEM_1 ITEM_2 ITEM_N
do
    command 1
    command 2
    command N
done
```

- The first variable (`ITEM_1`) is assigned to the variable (`VARIABLE_NAME`)
  and the code block is executed.
- The second variable (`ITEM_2`) is assigned to the variable (`VARIABLE_NAME`)
  and the code block is executed again.
- This happens for each itemn (`ITEM_N`) in the list.

Example
```sh
for COLOR in red green blue
do
    echo "COLOR: $COLOR"
done

# Output:
# COLOR: red
# COLOR: green
# COLOR: blue
```

Example 2
```sh
COLORS="red green blue"

for COLOR in $COLORS
do
    echo "COLOR: $COLOR"
done

# Output:
# COLOR: red
# COLOR: green
# COLOR: blue
```

Example 3
```sh
# Rename all files that end in _jpg_ by inserting today's date before the original filename.
PICTURES=$(ls *jpg)
DATE=$(date +%F)

for PICTURE in $PICTURES
do
    echo "Renaming ${PICTURE} to ${DATE}-${PICUTRE}"
    mv ${PICTURE} ${DATE}-${PICTURE}
done
```
