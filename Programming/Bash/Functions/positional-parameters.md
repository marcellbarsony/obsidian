# Positional parameters

Positional parameters are variables that contain the contents of the command
line.

## Syntax

```sh
$ script.sh parameter1 parameter2 parameter3

$0:"script.sh"
$1:"parameter1"
$2:"parameter2"
$3:"parameter3"
```

Example
```sh
./archive_user.sh elvis

USER=$1

echo "Executing script: $0"
echo "Archiving user: ${USER}"

# Lock the account
passwd -l ${USER}

# Create an archive of the home directory
tar cf /archives/${USER}.tar.gx /home/${USER}
```

### All parameters

Access all the positional parameters from `$1` to `$9` with `$@`
