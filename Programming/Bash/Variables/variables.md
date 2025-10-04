# Variables

## Valid syntax

```sh
VARIABLE_NAME="Value"
```

```sh
FIRST3LETTERS="ABC"
FIRST_THREE_LETTERS="ABC"
firstThreeLetters="ABC"
_FIRST3LETTERS="ABC"
```

Example
```sh
MY_SHELL="bash"
echo "I like the $VARIABLE_NAME shell"
echo "I like the ${VARIABLE_NAME} shell"
```

## Invalid syntax

```sh
3LETTERS="ABC"
first-three-letters="ABC"
first@Three@Letters="ABC"
```

## Command output to a variable

```sh
SERVER_NAME=$(hostname)
echo "This script is running on ${SERVER_NAME}."
```

## Quotation marks

**Single vs. double quotation marks**

It's recommended to use single quotes when we want to make sure that nothing is
changed in the output.<br>
We have to use double quotes to evaluate variables between them and output the
value of the variable.

## Variable scope

Variables have to be defined before they are used.

### Global variable

Every variable is global by default.

```sh
my_function() {
    GLOBAL_VAR=1
}

# GLOBAL_VAR is not available yet.
echo $GLOBAL_VAR
my function
# GLOBAL_VAR is now available
echo $GLOBAL_VAR
```

### Local variable

- Can only be accessed within the function
- Only functions can have local variables
- Best practice to keep variables local in functions
- Created using the local keyword

```sh
my_function() {
  local GLOBAL_VAR=1
}
```
