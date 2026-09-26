# Repository Instructions

## Python

This project requires Python 3.11 or newer. On Windows, always use the Python 3.13 launcher explicitly for every Python command:

- `py -3.13`
- `py -3.13 -m pytest`
- `py -3.13 -m pip`

Never use unversioned `python`, `python3`, or `pip` commands in this repository. Python 3.10 is intentionally installed for a separate project and is incompatible with Logscan because Logscan uses features such as `datetime.UTC`.
