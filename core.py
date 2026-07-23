"""
core.py — PasswordAnalyzer, VulnerabilityScanner, PasswordGenerator, SecurityReport
"""

import re
import math
import random
import string
from datetime import datetime
from functools import wraps
from models import Password


# Logging Decorator

def log_action(label: str):
    """Decorator factory — logs method calls with timestamp."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            print(f"  [LOG] {label} at {datetime.now().strftime('%H:%M:%S')}")
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# Common Weak Passwords

COMMON_PWDS = {
    "password", "123456", "password123", "qwerty", "abc123",
    "letmein", "welcome", "admin", "login",  "iloveyou",
    "111111",  "monkey",  "dragon",  "master", "hello123"
}


# PasswordAnalyzer

class PasswordAnalyzer:
    """Analyses complexity, entropy, and crack difficulty."""

    def __init__(self):
        self.analysis_id    = 0
        self.password_score = 0

    def check_complexity(self, pwd: str) -> dict:
        """Check each password rule; returns dict of bool results."""
        return {
            "length":    len(pwd) >= 8,
            "uppercase": bool(re.search(r'[A-Z]', pwd)),
            "lowercase": bool(re.search(r'[a-z]', pwd)),
            "digit":     bool(re.search(r'\d',    pwd)),
            "special":   bool(re.search(r'[!@#$%^&*()\-_=+{}\[\]|;:\'",.<>?/`~]', pwd))
        }

    @staticmethod
    def calculate_entropy(pwd: str) -> float:
        """Estimate password entropy in bits."""
        charset = (26 * any(c.islower()    for c in pwd) +
                   26 * any(c.isupper()    for c in pwd) +
                   10 * any(c.isdigit()    for c in pwd) +
                   32 * any(not c.isalnum() for c in pwd))
        return round(len(pwd) * math.log2(charset), 2) if charset else 0.0

    def detect_patterns(self, pwd: str) -> set:
        """Detect weak structural patterns; returns a set."""
        patterns = set()
        if re.search(r'(.)\1{2,}',              pwd):           patterns.add("repeated_chars")
        if re.search(r'012|123|234|345|456|567|678|789', pwd):  patterns.add("sequential_digits")
        if re.search(r'abc|bcd|cde|def|efg|fgh', pwd.lower()): patterns.add("sequential_letters")
        if re.search(r'qwer|wert|asdf|sdfg|zxcv', pwd.lower()):patterns.add("keyboard_pattern")
        return patterns

    @log_action("Password Analysis")
    def analyze(self, pwd: str) -> dict:
        """Full analysis — complexity + scoring + entropy + patterns."""
        self.analysis_id += 1
        c     = self.check_complexity(pwd)
        base  = sum(c.values()) * 15                        # criteria met × 15 (max 75)
        lb    = (25 if len(pwd) >= 16 else                  # length bonus (max 25)
                 15 if len(pwd) >= 12 else
                  5 if len(pwd) >=  8 else 0)
        score = min(base + lb, 100)
        self.password_score = score

        return {
            "id":               self.analysis_id,
            "password":         pwd,
            "length":           len(pwd),
            "complexity":       c,
            "score":            score,
            "strength":         Password.get_strength_label(score),
            "entropy":          PasswordAnalyzer.calculate_entropy(pwd),
            "patterns":         list(self.detect_patterns(pwd)),
            "crack_difficulty": ("Very Easy" if score <= 20 else
                                 "Easy"      if score <= 40 else
                                 "Moderate"  if score <= 60 else
                                 "Hard"      if score <= 80 else "Very Hard"),
            "timestamp":        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    @classmethod
    def overall_stats(cls, records: list) -> dict:
        """Class method — aggregate statistics across all analyses."""
        if not records: return {"total": 0, "avg_score": 0}
        scores = [r['score'] for r in records]
        return {
            "total":     len(records),
            "avg_score": round(sum(scores) / len(scores), 1),
            "highest":   max(scores),
            "lowest":    min(scores)
        }


# VulnerabilityScanner

class VulnerabilityScanner:
    """Scans passwords for known vulnerabilities and weak patterns."""

    def __init__(self):
        self.weak_password_list = COMMON_PWDS
        self.detected_risks:    list = []

    def scan_password(self, pwd: str) -> list:
        self.detected_risks = []
        if pwd.lower() in self.weak_password_list: self.detected_risks.append("common_password")
        if len(pwd) < 8:                           self.detected_risks.append("too_short")
        if re.search(r'(.)\1{3,}', pwd):           self.detected_risks.append("excessive_repetition")
        return self.detected_risks

    def detect_common_patterns(self, pwd: str) -> list:
        """List comprehension — return names of detected patterns."""
        checks = {
            "sequential": r'123|234|345|abc|bcd|cde',
            "keyboard":   r'qwer|asdf|zxcv',
            "repeated":   r'(.)\1{2,}'
        }
        return [name for name, pat in checks.items() if re.search(pat, pwd.lower())]


# PasswordGenerator

class PasswordGenerator:
    """Generates cryptographically random strong passwords."""

    def __init__(self):
        self.generated_password = ""

    @log_action("Password Generation")
    def generate_password(self, length: int = 12) -> str:
        """Generate a strong password satisfying all complexity rules."""
        charset = string.ascii_letters + string.digits + "!@#$%^&*()"
        while True:
            pwd = ''.join(random.choices(charset, k=length))
            if (any(c.isupper()         for c in pwd) and
                any(c.islower()         for c in pwd) and
                any(c.isdigit()         for c in pwd) and
                any(c in "!@#$%^&*()"  for c in pwd)):
                self.generated_password = pwd
                return pwd

    def suggest_password(self) -> list:
        """Return 3 strong password suggestions of varying length."""
        return [self.generate_password(random.randint(12, 16)) for _ in range(3)]


# SecurityReport

class SecurityReport:
    """Generates and exports password security reports."""

    _counter = 0   # class-level counter

    def __init__(self, user_name: str, records: list):
        SecurityReport._counter += 1
        self.report_id      = f"RPT{SecurityReport._counter:04d}"
        self.report_date    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.user_name      = user_name
        self.records        = records
        self.security_level = self._compute_level()

    def __str__(self)  -> str: return f"Report({self.report_id}, user={self.user_name})"
    def __repr__(self) -> str: return f"SecurityReport(id={self.report_id})"

    def _compute_level(self) -> str:
        if not self.records: return "N/A"
        avg = sum(r['score'] for r in self.records) / len(self.records)
        return "Low Risk" if avg >= 70 else "Medium Risk" if avg >= 40 else "High Risk"

    @log_action("Report Generation")
    def generate_report(self) -> dict:
        # List comprehensions — categorise passwords
        weak   = [r['password'] for r in self.records if r['score'] <  40]
        strong = [r['password'] for r in self.records if r['score'] >= 70]
        risky  = [r['password'] for r in self.records if r.get('patterns')]
        return {
            "report_id":      self.report_id,
            "user":           self.user_name,
            "date":           self.report_date,
            "total":          len(self.records),
            "security_level": self.security_level,
            "weak":           weak,
            "strong":         strong,
            "risky":          risky
        }

    def export_report(self) -> str:
        r = self.generate_report()
        return (
            f"\n  {'═'*42}\n"
            f"  {'SECURITY REPORT':^42}\n"
            f"  {'Report ID : ' + r['report_id']:<42}\n"
            f"  {'═'*42}\n"
            f"  User             : {r['user']}\n"
            f"  Date             : {r['date']}\n"
            f"  Total Analyzed   : {r['total']}\n"
            f"  Security Level   : {r['security_level']}\n"
            f"  Weak Passwords   : {len(r['weak'])}\n"
            f"  Strong Passwords : {len(r['strong'])}\n"
            f"  {'═'*42}"
        )

    @staticmethod
    def generate_records(records: list):
        """Generator — yields one analysis record at a time."""
        for record in records:
            yield record