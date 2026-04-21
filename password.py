#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Jose J. Cintron
# SPDX-License-Identifier: Apache-2.0
"""
password.py - Core password-generation library


How to use the library
# my_script.py
from password import Password

# Minimal invocation - defaults to 16 characters using all four sets
pw1 = Password()
print(pw1)                     # e.g. "v]g7M9$B!eR%k2qX"

# Custom length + custom rule (string form)
pw2 = Password(length=24, complexity="UL")
print(pw2.password)           # clear-text password
print(pw2.rule_string())      # → "lu"

# Using the factory helpers (immutable "mutators")
pw3 = pw2.with_length(30).with_complexity("S")
print(pw3)             # only special characters, length 30

"""

# ----------------------------------------------------------------------
# Standard library imports
# ----------------------------------------------------------------------
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Iterable,
    Tuple,
    List,
    Iterator,
    Union,
    overload,
)

# ----------------------------------------------------------------------
# Public constants (easy to tune from the outside)
# ----------------------------------------------------------------------
DEFAULT_LENGTH = 16          # used when the caller does not supply a length
MIN_LENGTH = 8               # lower bound enforced for security reasons
ALL_CHARSETS = (True, True, True, True)   # (lower, upper, digit, special)

# ----------------------------------------------------------------------
# Enum describing the four possible character groups
# ----------------------------------------------------------------------
class CharSet(Enum):
    """Logical groups of characters used for password generation.

    Members
    -------
    LOWER
        ``a-z``
    UPPER
        ``A-Z``
    DIGIT
        ``0-9``
    SPECIAL
        All punctuation characters from :pymod:`string.punctuation`.
    """

    LOWER   = auto()
    UPPER   = auto()
    DIGIT   = auto()
    SPECIAL = auto()

    @property
    def characters(self) -> str:
        """Return the concrete characters belonging to the enum member."""
        return {
            CharSet.LOWER:   string.ascii_lowercase,
            CharSet.UPPER:   string.ascii_uppercase,
            CharSet.DIGIT:   string.digits,
            CharSet.SPECIAL: string.punctuation,
        }[self]

# ----------------------------------------------------------------------
# Helper that parses/validates/pretty‑prints the *complexity rule*
# ----------------------------------------------------------------------
class Complexity:
    """Parse, validate and format the 4-boolean complexity rule.

    The internal representation is a ``Tuple[bool, bool, bool, bool]`` in the
    order ``(lower, upper, digit, special)``.
    """

    # Mapping from user‑visible tokens to the corresponding :class:`CharSet`.
    _letter_to_set = {
        "L": CharSet.LOWER,
        "U": CharSet.UPPER,
        "D": CharSet.DIGIT,
        "N": CharSet.DIGIT,          # “N” is accepted as a synonym for “D”
        "S": CharSet.SPECIAL,
    }

    @staticmethod
    def _as_bool_tuple(flags: Iterable[bool]) -> Tuple[bool, bool, bool, bool]:
        """
        Normalise any iterable of truthy values to a strict four-element tuple.

        Raises
        ------
        ValueError
            If the iterable does not contain exactly four items or if *all*
            flags are ``False``.
        """
        tup = tuple(bool(f) for f in flags)
        if len(tup) != 4:
            raise ValueError("Complexity must contain exactly four boolean values.")
        if not any(tup):
            raise ValueError("At least one character set must be enabled.")
        return tup                     # type: ignore[return-value]

    @classmethod
    def from_string(cls, s: str) -> Tuple[bool, bool, bool, bool]:
        """
        Parse a rule string such as ``'ULNS'`` (order does not matter).

        Allowed letters are ``L``, ``U``, ``D``/``N`` and ``S``.
        """
        s = s.upper()
        chosen = [False, False, False, False]   # L, U, D, S
        for ch in s:
            if ch not in cls._letter_to_set:
                raise ValueError(
                    f"Invalid token {ch!r} - allowed letters are L, U, D/N, S."
                )
            cs = cls._letter_to_set[ch]
            idx = list(CharSet).index(cs)      # 0=L,1=U,2=D,3=S
            chosen[idx] = True
        return cls._as_bool_tuple(chosen)

    @classmethod
    def from_iterable(cls, it: Iterable[bool]) -> Tuple[bool, bool, bool, bool]:
        """Validate an arbitrary iterable of booleans."""
        return cls._as_bool_tuple(it)

    @staticmethod
    def to_short_string(comp: Tuple[bool, bool, bool, bool]) -> str:
        """Compact representation - e.g. ``'luS'``."""
        tokens = ("l", "u", "d", "s")
        return "".join(tok for flag, tok in zip(comp, tokens) if flag)

    @staticmethod
    def to_long_string(comp: Tuple[bool, bool, bool, bool]) -> str:
        """
        Verbose representation - e.g. ``'LC, UC, D, SC'``.
        Returns an empty string if all flags are ``False`` (should never happen).
        """
        tokens = ("LC", "UC", "D", "SC")
        return ", ".join(token for flag, token in zip(comp, tokens) if flag)

# ----------------------------------------------------------------------
# Internal pure password generator - easy to unit‑test
# ----------------------------------------------------------------------
def _generate_password(
    length: int,
    required_sets: Tuple[CharSet, ...],
    rng: secrets.SystemRandom,
) -> str:
    """
    Return a *length*-character password that contains **at least one**
    character from every member of *required_sets*.

    Preconditions (checked by the caller):
        * ``len(required_sets) <= length``
        * ``required_sets`` is non-empty
    """
    # Union of all allowed characters
    pool = "".join(cs.characters for cs in required_sets)

    # One guaranteed character from each required set
    pwd_chars: List[str] = [rng.choice(cs.characters) for cs in required_sets]

    # Fill the rest randomly from the full pool
    pwd_chars.extend(rng.choice(pool) for _ in range(length - len(pwd_chars)))

    # Shuffle so the "seed" characters are not in predictable positions
    rng.shuffle(pwd_chars)
    return "".join(pwd_chars)

# ----------------------------------------------------------------------
# Immutable public API - the class users will import
# ----------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Password:
    """
    Immutable container for a generated password.

    Parameters
    ----------
    length : int, optional
        Desired password length (default ``16``). Must be ``>= 8``.
    complexity : tuple[bool, bool, bool, bool] | Iterable[bool] | str, optional
        Which character groups to use. Accepted forms:

        * a 4-tuple/list of booleans - order is ``(lower, upper, digit, special)``.
        * a string such as ``"ULN"`` - order does not matter; ``N`` == digit.
        * ``None`` - defaults to ``(True, True, True, True)`` (all groups).

    The class validates inputs, normalises the rule, creates a cryptographically
    secure password and then presents a read-only API that mimics a plain string.
    """

    # ---------------------- public fields ----------------------
    length: int = field(default=DEFAULT_LENGTH)
    complexity: Union[
        Tuple[bool, bool, bool, bool],
        Iterable[bool],
        str,
    ] = field(default=ALL_CHARSETS)

    # ---------------------- private helpers --------------------
    _rng: secrets.SystemRandom = field(
        default_factory=secrets.SystemRandom, repr=False, compare=False
    )
    _password: str = field(init=False, repr=False)

    # ---------------------- post‑init work --------------------
    def __post_init__(self) -> None:
        """Validate arguments and generate the password."""
        # Length check
        if self.length < MIN_LENGTH:
            raise ValueError(f"Length must be >= {MIN_LENGTH}; got {self.length}")

        # Normalise the complexity argument
        if isinstance(self.complexity, str):
            comp_tuple = Complexity.from_string(self.complexity)
        elif isinstance(self.complexity, (list, tuple)):
            comp_tuple = Complexity.from_iterable(self.complexity)   # type: ignore[arg-type]
        else:
            raise TypeError(
                "Complexity must be a 4-tuple/list of bools or a string like 'ULN'."
            )

        # Store the canonical tuple on the frozen instance
        object.__setattr__(self, "complexity", comp_tuple)

        # Determine which CharSet members are required
        required = tuple(cs for flag, cs in zip(comp_tuple, CharSet) if flag)

        # Generate the password
        generated = _generate_password(self.length, required, self._rng)
        object.__setattr__(self, "_password", generated)

    # ---------------------- public API -----------------------
    @property
    def password(self) -> str:
        """Return the clear-text password."""
        return self._password

    def rule_string(self) -> str:
        """Short, human-readable representation (e.g. ``'luS'``)."""
        return Complexity.to_short_string(self.complexity)   # type: ignore[arg-type]

    # ---------------------- dunder methods -------------------
    def __str__(self) -> str:
        """``str(password)`` returns only the password itself."""
        return self._password

    def __repr__(self) -> str:
        """Debug representation - never leaks the secret."""
        return (
            f"{self.__class__.__name__}"
            f"(length={self.length}, complexity={self.complexity})"
        )

    def __len__(self) -> int:
        """Length of the generated password (identical to ``self.length``)."""
        return len(self._password)

    def __iter__(self) -> Iterator[str]:
        """Iterate over the password characters."""
        return iter(self._password)

    @overload
    def __getitem__(self, key: int) -> str: ...

    @overload
    def __getitem__(self, key: slice) -> str: ...

    def __getitem__(self, key: Union[int, slice]) -> str:
        """Indexing / slicing - forwards to the underlying string."""
        return self._password[key]

    def __eq__(self, other: object) -> bool:
        """Equality check against another ``Password`` or a plain ``str``."""
        if isinstance(other, Password):
            return self._password == other._password
        if isinstance(other, str):
            return self._password == other
        return NotImplemented

    # ---------------------- immutable “mutators” -------------
    def with_length(self, new_length: int) -> "Password":
        """Return a new instance with a different length, same rule."""
        return Password(length=new_length, complexity=self.complexity)

    def with_complexity(
        self, new_complexity: Union[Iterable[bool], str]
    ) -> "Password":
        """Return a new instance with a different rule, same length."""
        return Password(length=self.length, complexity=new_complexity)

    # ---------------------- concatenation --------------------
    def __add__(self, other: Union["Password", str]) -> "Password":
        """Concatenate two passwords (or a password with a plain string)."""
        if isinstance(other, Password):
            new_pw = self._password + other._password
        elif isinstance(other, str):
            new_pw = self._password + other
        else:
            return NotImplemented

        tmp = Password(length=len(new_pw), complexity=self.complexity)
        object.__setattr__(tmp, "_password", new_pw)
        return tmp

    def __radd__(self, other: str) -> "Password":
        """Right-hand version of ``__add__`` - enables ``'prefix' + Password``."""
        if isinstance(other, str):
            new_pw = other + self._password
            tmp = Password(length=len(new_pw), complexity=self.complexity)
            object.__setattr__(tmp, "_password", new_pw)
            return tmp
        return NotImplemented

    # ---------------------- explicit factory -----------------
    @classmethod
    def from_params(
        cls,
        *,
        length: int | None = None,
        complexity: Union[Iterable[bool], str, None] = None,
    ) -> "Password":
        """
        Convenience constructor that supplies default values before delegating
        to the dataclass ``__init__``.
        """
        length = length if length is not None else DEFAULT_LENGTH
        complexity = complexity if complexity is not None else ALL_CHARSETS
        return cls(length=length, complexity=complexity)
