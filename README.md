# Password Strength Analyser
The Cybersecurity Password Strength Analyzer is a Python-based, fully offline console application
that evaluates the security of user-supplied passwords against modern cybersecurity standards. The
system scores passwords on a 0-to-100 scale derived from five complexity dimensions — minimum
length, uppercase letters, lowercase letters, digits, and special characters — combined with a lengthweighted bonus that rewards longer passwords.

Beyond static rule checking, the application detects structural weaknesses including sequential
character runs, keyboard-walk patterns (e.g. "qwerty"), repeated characters, and membership in a
dictionary of commonly breached passwords. For each analysis, the tool calculates Shannon entropy in
bits and estimates crack difficulty on a five-tier scale from Very Easy to Very Hard. Users can register
accounts, log in, maintain a full per-session analysis history, generate cryptographically random
compliant passwords, and export results as JSON and CSV reports.

The project is organised across three Python modules — models.py, core.py, and main.py — totalling
624 lines of code with zero third-party dependencies. The architecture comprehensively demonstrates:
abstract base classes, multi-level OOP inheritance, encapsulation, polymorphism, decorators,
generators, recursion, lambda functions, list comprehensions, static and class methods, magic methods,
and structured exception handling, making it simultaneously a production-quality security tool and a
complete Python learning showcase.

Testing confirms accurate classification across all strength levels, correct dictionary detection, reliable
pattern recognition, and round-trip fidelity of JSON/CSV persistence. The application runs on any
platform supporting Python 3.x — Windows, macOS, or Linux — without installation of additional
packages.
