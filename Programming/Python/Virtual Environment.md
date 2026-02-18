---
id: Virtual Environment
aliases: []
tags:
  - Programming/Python/Virtual-Environment
---

# Virtual Environment

A virtual environment is a Python environment such that the Python interpreter,
libraries and scripts installed into it are isolated from those installed in
other virtual environments, and (by default) any libraries installed in a
"system" Python, i.e., one which is installed as part of the operating system.

___

<!-- Initialize {{{-->
## Initialize

Initialize venv

```sh
python -m venv [project_dir]/[venv_name] --system-site-packages
```

```sh
python3 -m venv venv
```

___
<!-- }}} -->

<!-- Activate {{{-->
## Activate

Activate venv

```sh
source [project_dir]/[venv_name]/bin/activate
```

```sh
source venv/bin/activate
```

___
<!-- }}} -->

<!-- Environment Info {{{-->
## Environment Info

Check active environment

```sh
which python
```

List local (*environment*) packages

```sh
pip list --local
```

___
<!-- }}} -->

<!-- Delete & Deactivate {{{-->
## Delete & Deactivate

Deactivate Environment

```sh
deactivate
```

To delete the virtual environment, simply delete the environment folder

___
<!-- }}} -->

<!-- Requirements {{{-->
## Requirements

Generate Requirements

```sh
pip freeze > requirements.txt
```

Install Requirements

```sh
pip install -r requirements.txt
```

___
<!-- }}} -->
