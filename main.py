'''
main.py — PasswordStrengthSystem (composes all modules) + menu-driven interface
'''

import os
import json
import csv
from models import User, Admin
from core   import PasswordAnalyzer, VulnerabilityScanner, PasswordGenerator, SecurityReport


# Custom Exceptions

class EmptyPasswordError(Exception): pass
class WeakPasswordError  (Exception): pass
class InvalidUserError   (Exception): pass


# Password Strength System

class PasswordStrengthSystem:
    # Central system — Composition: contains Password Analyzer, Vulnerability Scanner, Password Generator, and Security Report objects.

    DATA_FILE    = "data/users.json"
    HISTORY_FILE = "data/history.json"
    REPORT_CSV   = "data/reports.csv"

    def __init__(self):
        self.users:            dict = {}      # email → User
        self.analysis_records: list = []
        self.reports:          list = []
        self.current_user:     User = None
        # Composition
        self.analyzer  = PasswordAnalyzer()
        self.scanner   = VulnerabilityScanner()
        self.generator = PasswordGenerator()
        os.makedirs("data", exist_ok=True)

    def __str__(self)  -> str: return f"System(users={len(self.users)}, analyses={len(self)})"
    def __repr__(self) -> str: return f"PasswordStrengthSystem(users={list(self.users.keys())})"
    def __len__(self)  -> int: return len(self.analysis_records)   # total analyses


    # User Management

    def register_user(self, name: str, email: str, pwd: str) -> bool:
        if email in self.users:
            print("  ✘ Email already registered."); return False
        uid = f"U{len(self.users)+1:04d}"
        self.users[email] = User(uid, name, email, pwd)
        print(f"  ✔ Registered successfully: {name} ({email})")
        return True

    def login(self, email: str, pwd: str) -> bool:
        if email not in self.users:           raise InvalidUserError("User not found.")
        if not self.users[email].verify_password(pwd): raise InvalidUserError("Wrong password.")
        self.current_user = self.users[email]
        print(f"  ✔ Welcome back, {self.current_user._name}!")
        return True

    def _require_login(self) -> bool:
        if self.current_user is None: print("  ✘ Please login first."); return False
        return True


    # Password Analysis

    def analyze_password(self, pwd: str) -> dict:
        if not pwd.strip(): raise EmptyPasswordError("Password cannot be empty.")
        result          = self.analyzer.analyze(pwd)
        result['risks'] = self.scanner.scan_password(pwd)
        if self.current_user: self.current_user.add_to_history(result)
        self.analysis_records.append(result)
        _print_result(result)
        return result


    # Recursive History Search

    def search_history(self, keyword: str, records: list = None, idx: int = 0) -> list:
        # Recursively search password history by strength label.
        if records is None:
            records = (self.current_user.view_history() if self.current_user is not None
                       else self.analysis_records)
        if idx >= len(records): return []
        match = ([records[idx]]
                 if keyword.lower() in records[idx].get('strength', '').lower()
                 else [])
        return match + self.search_history(keyword, records, idx + 1)


    # Generator Usage
    def stream_records(self):
        """Expose the SecurityReport generator to iterate records one by one."""
        records = (self.current_user.view_history() if self.current_user is not None
                   else self.analysis_records)
        return SecurityReport.generate_records(records)


    # Password Generation
    def generate_strong_password(self, length: int = 12) -> str:
        pwd = self.generator.generate_password(length)
        print(f"\n  Generated  : {pwd}")
        print("  Suggestions:")
        for i, s in enumerate(self.generator.suggest_password(), 1):
            print(f"    {i}. {s}")
        return pwd


    # Reporting

    def generate_reports(self):
        if not self._require_login(): return
        records = self.current_user.view_history()
        rep     = SecurityReport(self.current_user._name, records)
        self.reports.append(rep)
        print(rep.export_report())
        print(f"\n  Overall Stats : {self.analyzer.overall_stats(records)}")

    def generate_all_reports(self) -> list:
        return [SecurityReport(u._name, u.view_history()).generate_report()
                for u in self.users.values()]

    def get_all_users(self) -> list:
        return [u.display_details() for u in self.users.values()]

    # File Handling
    def save_data(self):
        try:
            # JSON — user profiles + individual histories
            data = {
                e: {"name":    u._name,            "email":   u._email,
                    "history": u.password_history,  "score":   u.security_score}
                for e, u in self.users.items()
            }
            with open(self.DATA_FILE,    'w') as f: json.dump(data,                  f, indent=2)
            with open(self.HISTORY_FILE, 'w') as f: json.dump(self.analysis_records, f, indent=2)

            # CSV — flattened analysis report
            if self.analysis_records:
                fields = ["id", "password", "length", "score", "strength",
                          "crack_difficulty", "timestamp"]
                with open(self.REPORT_CSV, 'w', newline='') as f:
                    w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
                    w.writeheader()
                    w.writerows(self.analysis_records)

            print("  ✔ Data saved to data/ folder.")
        except Exception as e:
            print(f"  ✘ Save error: {e}")

    def load_data(self):
        try:
            if os.path.exists(self.DATA_FILE):
                with open(self.DATA_FILE) as f: saved = json.load(f)
                for email, d in saved.items():
                    u = User(f"U{len(self.users)+1:04d}", d['name'], email, "")
                    u.password_history = d.get('history', [])
                    u.security_score   = d.get('score', 0)
                    self.users[email]  = u
            if os.path.exists(self.HISTORY_FILE):
                with open(self.HISTORY_FILE) as f:
                    self.analysis_records = json.load(f)
            print("  ✔ Data loaded successfully.")
        except FileNotFoundError:
            print("  No saved data found. Starting fresh.")
        except Exception as e:
            print(f"  ✘ Load error: {e}")



# Helper: print analysis result

def _print_result(r: dict):
    c  = r['complexity']
    ck = lambda b: '✔' if b else '✘'    # lambda helper
    print(f"\n  {'─'*42}")
    print(f"  {'Password Analysis':^42}")
    print(f"  {'─'*42}")
    print(f"  Length   ({r['length']:2d} chars)  : {ck(c['length'])}")
    print(f"  Uppercase              : {ck(c['uppercase'])}")
    print(f"  Lowercase              : {ck(c['lowercase'])}")
    print(f"  Digit                  : {ck(c['digit'])}")
    print(f"  Special Character      : {ck(c['special'])}")
    print(f"  {'─'*42}")
    print(f"  Entropy                : {r['entropy']} bits")
    print(f"  Score                  : {r['score']}/100")
    print(f"  Strength               : {r['strength']}")
    print(f"  Crack Difficulty       : {r['crack_difficulty']}")
    if r.get('risks'):    print(f"  Risks Detected         : {', '.join(r['risks'])}")
    if r.get('patterns'): print(f"  Patterns Found         : {', '.join(r['patterns'])}")
    print(f"  {'─'*42}\n")


# Lambda Sort Helpers

sort_by_score = lambda records: sorted(records, key=lambda r: r['score'],               reverse=True)
sort_by_risk  = lambda records: sorted(records, key=lambda r: len(r.get('risks', [])),  reverse=True)


# Menu 

MENU = """
  ╔══════════════════════════════════════════╗
  ║    Cybersecurity Password Analyzer       ║
  ╠══════════════════════════════════════════╣
  ║  1. Register User      6. Security Report║
  ║  2. Login              7. Search History ║
  ║  3. Analyze Password   8. Save Data      ║
  ║  4. Generate Password  9. Load Data      ║
  ║  5. View History       0. Exit           ║
  ╚══════════════════════════════════════════╝"""


def main():
    system = PasswordStrengthSystem()
    print("\n  ╔══════════════════════════════════════════╗")
    print(  "  ║  Cybersecurity Password Strength Analyzer║")
    print(  "  ╚══════════════════════════════════════════╝")

    while True:
        print(MENU)
        choice = input("  Choose [0–9]: ").strip()

        try:
            if choice == '1':
                name  = input("  Name     : ").strip()
                email = input("  Email    : ").strip()
                pwd   = input("  Password : ").strip()
                system.register_user(name, email, pwd)

            elif choice == '2':
                email = input("  Email    : ").strip()
                pwd   = input("  Password : ").strip()
                try:   system.login(email, pwd)
                except InvalidUserError as e: print(f"  ✘ {e}")

            elif choice == '3':
                pwd = input("  Password to analyze: ").strip()
                try:   system.analyze_password(pwd)
                except EmptyPasswordError as e: print(f"  ✘ {e}")

            elif choice == '4':
                try:
                    raw = input("  Length (12–20, default 12): ").strip()
                    l   = int(raw) if raw else 12
                    system.generate_strong_password(max(12, min(l, 20)))
                except ValueError:
                    print("  ✘ Invalid length — must be a number.")

            elif choice == '5':
                if not system._require_login(): continue
                history = system.current_user.view_history()
                if not history: print("  No history yet."); continue
                print(f"\n  History — {len(history)} record(s) sorted by score:")
                for i, r in enumerate(sort_by_score(history), 1):
                    print(f"    {i}. Score: {r['score']:3d}/100 | {r['strength']:<12} | {r['timestamp']}")

            elif choice == '6':
                system.generate_reports()

            elif choice == '7':
                kw  = input("  Keyword (e.g. Weak / Strong / Very): ").strip()
                res = system.search_history(kw)
                print(f"\n  Found {len(res)} match(es) for '{kw}':")
                for r in res:
                    print(f"    Score: {r['score']:3d}/100 | {r['strength']:<12} | {r['timestamp']}")

            elif choice == '8': system.save_data()
            elif choice == '9': system.load_data()
            elif choice == '0':
                system.save_data()
                print("  Goodbye! Stay secure. 🔒"); break
            else:
                print("  Invalid choice — enter 0 to 9.")

        except KeyboardInterrupt:
            print("\n  Interrupted. Goodbye!"); break
        except Exception as e:
            print(f"  ✘ Unexpected error: {e}")


if __name__ == "__main__":
    main()
