# Virtual Environment

A virtual environment is a Python environment such that the Python interpreter,
libraries and scripts installed into it are isolated from those installed in
other virtual environments, and (by default) any libraries installed in a
"system" Python, i.e., one which is installed as part of the operating system.

## Initialize & Activate

```sh
# Initialize venv
python -m venv [project_dir]/[venv_name] --system-site-packages

# Activate venv
source [project_dir]/[venv_name]/bin/activate
```

## Environment Info

```sh
# Check active environment
which python

# List local (environment) packages
pip list --local
```

## Delete & Deactivate

```sh
# Deactivate Environment
deactivate
```

To delete the virtual environment, simply delete the environment folder.

## Requirements

```sh
# Generate Requirements
pip freeze > requirements.txt

# Install Requirements
pip install -r requirements.txt
```
