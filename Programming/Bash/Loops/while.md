# While loop

## Syntax

```sh
while [ condition-is-true ]
do
  command 1
  command 2
  command N
done
```

**Infinite loop**

```sh
while true
do
  command 1
  sleep 1
done
```

Control the number of loops
```sh
INDEX=1
while [$INDEX -lt 6 ]
do
  echo "Creating project-${INDEX}"
  mkdir /usr/local/project-${INDEX}
  ((INDEX++))
done
```

Check user input
```sh
while [ "$CORRECT" != "y" ]
do
    read -p "Enter your name: " NAME
    read -p "Is ${NAME} correct?" CORRECT
done
```

Read a file line-by-line
```sh
# This example reads the fstab file line-by-line, printing the line number, following the actual line.
LINE_NUM=1
while read LINE
do
    echo "${LINE_NUM}: ${LINE}"
    ((LINE_NUM++))
done < /etc/fstab
```

REad the output of a command, line-by-line
```sh
grep xfs /etc/fstab | while read LINE
do
    echo "xfs: ${LINE}"
done

FS_NUM=1
grep xfs /etc/fstab | while read FS MP REST
do
  echo "${FS_NUM}: file system: ${FS}"
    echo "${FS_NUM}: mount point: ${MP}"
    ((FS_NUM++))
done
```
