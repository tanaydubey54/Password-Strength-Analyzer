"""
models.py — Core class hierarchy: 
Person (abstract), 
User, 
Admin, 
Password
"""

from abc import ABC, abstractmethod
import math


# Abstract Base

class Person(ABC):
    """Abstract base class - defines interface for all system users."""

    def __init__(self, uid: str, name: str, email: str):
        self._user_id = uid          # protected
        self._name    = name
        self._email   = email

    @abstractmethod
    def display_details(self) -> str:
        pass

    def update_profile(self, name: str = None, email: str = None):
        if name:  self._name  = name
        if email: self._email = email


# Derived: User

class User(Person):
    """Regular user — stores password history and security score."""

    def __init__(self, uid: str, name: str, email: str, pwd: str):
        super().__init__(uid, name, email)
        self.__pwd             = pwd            # private (encapsulation)
        self.password_history: list = []
        self.security_score:   int  = 0

    # Polymorphism
    def display_details(self) -> str:
        return f"[User]  {self._name} | {self._email} | Score: {self.security_score}"

    def __str__ (self) -> str:  return f"User({self._name})"
    def __repr__(self) -> str:  return f"User(id={self._user_id}, email={self._email})"
    def __len__ (self) -> int:  return len(self.password_history)   # total analyses
    def __bool__(self) -> bool: return True                          # always truthy

    def verify_password(self, pwd: str) -> bool: return self.__pwd == pwd

    def add_to_history(self, result: dict):
        self.password_history.append(result)
        self.security_score = result['score']

    def view_history(self) -> list: return self.password_history


# Derived: Admin

class Admin(Person):
    """Admin user — can manage users and generate global reports."""

    def __init__(self, uid: str, name: str, email: str, pwd: str, admin_id: str):
        super().__init__(uid, name, email)
        self.__pwd    = pwd             # private (encapsulation)
        self.admin_id = admin_id

    # Polymorphism
    def display_details(self) -> str:
        return f"[Admin] {self._name} | {self._email} | AdminID: {self.admin_id}"

    def __str__(self)  -> str: return f"Admin({self._name})"
    def __repr__(self) -> str: return f"Admin(id={self.admin_id})"

    def verify_password(self, pwd: str) -> bool: return self.__pwd == pwd


# Password

class Password:
    """Represents a password with static analysis utilities."""

    RULES   = ("min 8 chars", "uppercase letter", "lowercase letter", "digit", "special char")  # tuple
    _LEVELS = {                          # score → strength label
        (0,  20): "Very Weak",
        (21, 40): "Weak",
        (41, 60): "Moderate",
        (61, 80): "Strong",
        (81,100): "Very Strong",
    }

    def __init__(self, text: str):
        self.password_text = text
        self.length        = len(text)
        self.strength      = None

    def __str__(self)  -> str: return f"Password(len={self.length}, strength={self.strength})"
    def __repr__(self) -> str: return f"Password('{self.password_text[:2]}***')"
    def __len__(self)  -> int: return self.length

    @staticmethod
    def calculate_entropy(pwd: str) -> float:
        """Shannon entropy estimate based on charset size."""
        charset = (26 * any(c.islower()    for c in pwd) +
                   26 * any(c.isupper()    for c in pwd) +
                   10 * any(c.isdigit()    for c in pwd) +
                   32 * any(not c.isalnum() for c in pwd))
        return round(len(pwd) * math.log2(charset), 2) if charset else 0.0

    @classmethod
    def get_strength_label(cls, score: int) -> str:
        return next((v for (lo, hi), v in cls._LEVELS.items() if lo <= score <= hi), "Unknown")

    @classmethod
    def get_rules(cls) -> tuple:
        return cls.RULES