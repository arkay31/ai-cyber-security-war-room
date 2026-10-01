"""
CLI script to seed synthetic SOC events and attack scenarios into the War Room database.
"""

import sys
from backend.app.database import SessionLocal, init_db
from backend.app.services.mitre_service import MitreService
from backend.app.services.synthetic_generator import SyntheticGenerator


def main():
    print("[*] Initializing database and MITRE ATT&CK techniques...")
    init_db()
    with SessionLocal() as db:
        MitreService.seed_techniques(db)
        print("[*] Seeding synthetic attack scenarios:")
        print("    - Scenario 1: Brute Force -> Compromise -> Privilege Escalation -> Exfiltration")
        print("    - Scenario 2: Port Scan -> Reconnaissance -> Suspicious Process")
        print("    - Scenario 3: Suspicious Login -> Privilege Escalation -> Data Access")
        results = SyntheticGenerator.seed_all_scenarios(db)
        print("\n[+] Successfully generated and correlated synthetic events:")
        for k, v in results.items():
            print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
