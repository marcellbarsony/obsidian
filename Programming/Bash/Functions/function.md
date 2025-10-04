# Function

A function is a block of reusable code that performs an action and returns an
exit status.

## Define a function

```sh
function function-name() {
  # Code goes here
}

# or

function-name() {
  # Code goes here
}
```

## Call a function

```sh
hello() {
  echo "Hello!"
}

hello
```

Functions can call other functions
```sh
hello() {
  echo "Hello!"
  now
}

now () {
  echo "It's $(date +%r)"
}

hello
```
