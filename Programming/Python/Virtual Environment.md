# Virtual Environment

A virtual environment is a Python environment such that the Python interpreter,
libraries and scripts installed into it are isolated from those installed in
other virtual environments, and (by default) any libraries installed in a
"system" Python, i.e., one which is installed as part of the operating system.

## Initialize

Initialize venv

```sh
python -m venv [project_dir]/[venv_name] --system-site-packages
```

```sh
python3 -m venv venv
```

## Activate

Activate venv

```sh
source [project_dir]/[venv_name]/bin/activate
```

```sh
source venv/bin/activate
```

## Environment Info

Check active environment

```sh
which python
```

List local (*environment*) packages

```sh
pip list --local
```

## Delete & Deactivate

Deactivate Environment

```sh
deactivate
```

To delete the virtual environment, simply delete the environment folder

## Requirements

Generate Requirements

```sh
pip freeze > requirements.txt
```

Install Requirements

```sh
pip install -r requirements.txt
```
