# genPassword  

**Version:** 1.0 (first public release)  
**Author:** Jose J. Cintron – <l0rddarkr0ce@yahoo.com>

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)  
[![Python](https://img.shields.io/badge/python-3.11%2B-brightgreen.svg)](https://www.python.org/downloads/)

**genPassword** is a tiny, zero‑dependency library that generates cryptographically‑secure passwords.  
It ships with a small command‑line interface (`genPassword.py`) and a reusable Python API (`password.py`).  

---

## Table of Contents

- [genPassword](#genpassword)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Installation](#installation)
  - [Using the Library](#using-the-library)
  - [Configuration \& Options](#configuration--options)
  - [Contributing](#contributing)
  - [License](#license)

---

## Features

- **Fully deterministic API** – the `Password` class is immutable and hashable.  
- **Four character sets** – lower‑case, upper‑case, digits, special characters.  
- **Customizable length** (minimum 8 characters).  
- **Human‑readable rule strings** (`'ULN'`, `'luS'`, …).  
- **Zero third‑party dependencies** – only the Python standard library.  
- **CLI wrapper** for one‑liner password generation.  

---

## Installation

Because the project uses **only the standard library**, you can drop the two source files into any Python 3.11+ project, or install them via `pip` if you prefer an editable install.

```bash
# 1️⃣ Clone the repo
git clone https://github.com/your‑username/genPassword.git
cd genPassword

# 2️⃣ (Optional) create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3️⃣ Install in editable mode (adds the package to sys.path)
pip install -e .
```

> "Note: No external packages are required, so `requirements.txt` can be empty (see the Generating a requirements.txt section)."

---

## Using the Library

```python
from password import Password, Complexity

# 1️⃣ Minimal use – defaults to 16 characters, all sets
pw = Password()
print(pw)                     # e.g. "v]g7M9$B!eR%k2qX"
print(pw.rule_string())      # → "luS"

# 2️⃣ Custom length & rule (string form)
pw2 = Password(length=24, complexity="UL")
print(pw2.password)          # clear‑text password
print(pw2.rule_string())     # → "lu"

# 3️⃣ Custom rule as a tuple of booleans
pw3 = Password(length=30, complexity=(True, False, True, False))  # lower+digit only
print(pw3)

# 4️⃣ Immutable “mutators” – create a new instance with modified parameters
pw4 = pw2.with_length(32).with_complexity("S")   # only special chars, length 32
print(pw4)

# 5️⃣ Access the underlying rule in long form
print(Complexity.to_long_string(pw2.complexity))  # → "LC, UC"
```

All `Password` objects behave like plain strings:

```python
len(pw)               # → 16
pw[0]                 # first character
for ch in pw: ...     # iteration
pw == "mysecret"      # direct comparison with a str

```

---

## Configuration & Options

| Parameter | Type | Default | Meaning |
| ----------- | ------ | --------- | --------- |
| length | int | 16 | Desired password length (must be ≥ 8). |
| complexity | Tuple[bool, bool, bool, bool] \| str | (True, True, True, True) | Which character sets to include. Accepted forms: <br>• 4‑tuple/list of booleans ((True, False, True, False))<br>• String tokens ('LUDS', 'ULN', 'S', …) – order does not matter, N is an alias for digits. |
| Password.with_length(new_len) | method | – | Returns a new Password instance with the supplied length. |
| Password.with_complexity(new_rule) | method | – | Returns a new Password instance with the supplied rule. |

The helper class `Complexity` also provides:

- `Complexity.from_string('ULN')` → normalized tuple
- `Complexity.to_short_string(tuple)` → e.g. 'luS'
- `Complexity.to_long_string(tuple)` → e.g. 'LC, UC, D, SC'

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (git checkout -b my‑feature).
3. Write code (keep the standard‑library‑only rule unless a strong case is made).
4. Add/Update tests.
5. Run the test suite (pytest).
6. Submit a Pull Request with a clear description of the change.

Please respect the existing code style (PEP 8, type hints, and doc‑strings) and ensure the new code is covered by tests.

---

## License

This code is released under the Apache License, Version 2.0.

```text
Copyright © 2025–2026 Jose J. Cintron

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

```

For the full license text, see the LICENSE file in the repository.
