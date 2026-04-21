#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jose J. Cintron
# SPDX-License-Identifier: Apache-2.0
"""
   Program name: genPassword.py
   Version: 1.0
   Date Created: 2025/09/15
   Author: Jose J. Cintron
   E-mail: l0rddarkf0rce@yahoo.com

Description:
   Program to generate a password using a Password class. The class 
   generates a password, based on a given length and complexity rule.
      length (integer) := Cannot be less than 8 (default 16)
      complexity rule (tuple of bool) := Which character sets shall be
         used to generate the password. Represented as (LC, UC, D, SC)
         default is (True, True, True, True).

Typical usage:
   $ python genPassword.py -l 20 -c ULN
    aZ9$kL4!pR1tQ6mX!y2
    Password: aZ9$kL4!pR1tQ6mX!y2  [Complexity rule: (LC, UC, D), Length: 20]

Revision History:
   2025/09/15 - Original code created
   2026/04/20 - Code refactored
   2026/04/21 - Code documented, and the password class and its related
                functionality was moved to a separate module.
"""

# ----------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------
from argparse import ArgumentParser, Namespace

# ----------------------------------------------------------------------
# Local import - the pure library lives in ``password.py``
# ----------------------------------------------------------------------
from password import Password, Complexity, DEFAULT_LENGTH, MIN_LENGTH

# ----------------------------------------------------------------------
# CLI helpers
# ----------------------------------------------------------------------
def _build_arg_parser() -> ArgumentParser:
    """Create an :class:`argparse.ArgumentParser` with ``-l`` and ``-c`` options."""
    parser = ArgumentParser(
        prog="genPassword.py",
        description="Generate a secure password with configurable length and character sets.",
    )
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=DEFAULT_LENGTH,
        help=f"Desired length (default {DEFAULT_LENGTH}, minimum {MIN_LENGTH}).",
    )
    parser.add_argument(
        "-c",
        "--complexity",
        type=str,
        default="ULNS",
        help=(
            "Complexity rule - any combination of L, U, D/N, S. "
            "Example: 'UL' -> upper and lower case only."
        ),
    )
    return parser

def main() -> None:
    """Entry-point for the command-line interface."""
    args: Namespace = _build_arg_parser().parse_args()
    pw = Password(length=args.length, complexity=args.complexity)

    # Human‑readable output - the password itself, its rule and its length
    print(
        f"Password: {pw}  "
        f"[Complexity rule: ({Complexity.to_long_string(pw.complexity)}), "
        f"Length: {pw.length}]"
    )

if __name__ == "__main__":
    main()