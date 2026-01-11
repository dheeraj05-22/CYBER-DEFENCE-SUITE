# modules/phishing_simulator.py

import os
import csv
import random
import textwrap
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(os.path.dirname(BASE_DIR), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)
RESULT_CSV = os.path.join(REPORTS_DIR, "phishing_results.csv")

# A small set of safe, educational scenarios.
# Each scenario: {type, subject, sender, content, label, cues}
# - label: "phishing" or "legit"
# - cues: short list of reasons this is phishing (used for feedback)
_SCENARIOS = [
    {
        "type": "email",
        "subject": "Action Required: Verify Your Account Details",
        "sender": "support@yourbank-secure.com",
        "content": (
            "Dear Customer,\n\n"
            "We detected unusual activity on your account. Please verify your identity immediately by visiting:\n"
            "http://yourbank.verify-account.xyz/verify\n\n"
            "Failure to do so will result in temporary suspension.\n\n"
            "Regards,\nOnline Banking Support"
        ),
        "label": "phishing",
        "cues": ["suspicious sender domain", "urgent action", "odd URL"]
    },
    {
        "type": "email",
        "subject": "Your Amazon Order #12345 has been shipped",
        "sender": "order-update@amazon.in",
        "content": (
            "Hello,\n\n"
            "Your item has been shipped and will arrive in 3-5 business days.\n"
            "Track shipment here: https://amazon.in/track/12345\n\n"
            "Thanks for shopping with us!\nAmazon"
        ),
        "label": "legit",
        "cues": ["trusted sender domain", "no urgent demand", "valid link format"]
    },
    {
        "type": "text",
        "subject": "(SMS) Delivery problem",
        "sender": "CourierSvc",
        "content": (
            "URGENT: We couldn't deliver your parcel. Confirm address: http://courier-update.info/addr"
        ),
        "label": "phishing",
        "cues": ["shortened/corrupt URL", "urgency", "unknown domain"]
    },
    {
        "type": "email",
        "subject": "HR: Update your payroll details",
        "sender": "hr@company.local",
        "content": (
            "Hi,\n\nPlease update your payroll bank details for the next salary cycle by filling this internal form:\n"
            "https://intranet.company.local/forms/payroll\n\nThanks,\nHR Team"
        ),
        "label": "legit",
        "cues": ["internal domain", "proper formal tone", "no suspicious links"]
    },
    {
        "type": "email",
        "subject": "Reset your password now",
        "sender": "security-notice@googlesupport.com",
        "content": (
            "Dear user,\n\nWe have noticed suspicious login attempts. Reset your password:\n"
            "http://accounts.google.secure-reset.example.com\n\nSincerely,\nSupport"
        ),
        "label": "phishing",
        "cues": ["typo-squatted domain", "external link", "unexpected email"]
    },
    {
        "type": "email",
        "subject": "Invoice for your recent purchase",
        "sender": "billing@shop.example.com",
        "content": (
            "Hello,\nAttached is the invoice for your last order.\n\nThank you,\nShop Billing\n\n(Attachment: invoice.pdf)"
        ),
        "label": "legit",
        "cues": ["consistent sender", "normal business content"]
    },
]

def _init_csv():
    header = [
        "timestamp", "scenario_type", "subject", "sender", "label", "user_choice",
        "correct", "reasons_entered", "notes"
    ]
    if not os.path.exists(RESULT_CSV):
        with open(RESULT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(header)


def _save_result(row: dict):
    _init_csv()
    with open(RESULT_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            row.get("timestamp"),
            row.get("scenario_type"),
            row.get("subject"),
            row.get("sender"),
            row.get("label"),
            row.get("user_choice"),
            row.get("correct"),
            row.get("reasons_entered"),
            row.get("notes"),
        ])


def _wrap_text(s: str, width: int = 72):
    return "\n".join(textwrap.wrap(s, width))


def _present_scenario(s):
    print("\n" + "="*72)
    print(f"Type   : {s['type'].upper()}")
    print(f"From   : {s['sender']}")
    print(f"Subject: {s['subject']}\n")
    print(_wrap_text(s['content']))
    print("="*72 + "\n")


def _get_user_choice():
    while True:
        print("Choose -> [1] PHISHING   [2] LEGIT   [3] UNSURE   [q] Quit")
        ch = input("Your answer: ").strip().lower()
        if ch in ("1", "2", "3", "q"):
            return ch
        print("Invalid input. Enter 1, 2, 3 or q.")


def _feedback(scenario, user_choice, reasons):
    user_label = {"1": "phishing", "2": "legit", "3": "unsure"}.get(user_choice, "quit")
    correct = (user_label == scenario["label"])
    print("\n--- Feedback ---")
    if correct:
        print("✅ Correct!")
    else:
        print("❌ Not correct.")
    # show explanation but avoid giving 'how to phish'
    print("Expected : ", scenario["label"].upper())
    print("Why?     : ", "; ".join(scenario.get("cues", [])))
    if reasons:
        print("Your reasons: ", reasons)
    print("----------------\n")
    return correct


def run_phishing_simulator(n_rounds: int = 5):
    """
    Interactive demo for phishing awareness.
    - n_rounds: number of scenarios to present (default 5)
    """
    print("\n=== Phishing Awareness Simulator ===")
    print("You will be shown short simulated messages (emails/SMS).")
    print("For each one, choose whether it's PHISHING or LEGIT and briefly explain why.")
    print("This is for training/awareness only.\n")

    scenarios = _SCENARIOS.copy()
    random.shuffle(scenarios)

    _init_csv()
    rounds = min(n_rounds, len(scenarios))
    score = 0
    attempts = 0

    for i in range(rounds):
        s = scenarios[i]
        _present_scenario(s)
        choice = _get_user_choice()
        if choice == "q":
            print("Exiting phishing simulator.")
            break

        reasons = input("(optional) What cues did you notice? (short) ").strip()
        correct = _feedback(s, choice, reasons)

        # Save result row
        row = {
            "timestamp": datetime.now().isoformat(),
            "scenario_type": s["type"],
            "subject": s["subject"],
            "sender": s["sender"],
            "label": s["label"],
            "user_choice": {"1":"phishing","2":"legit","3":"unsure"}.get(choice),
            "correct": correct,
            "reasons_entered": reasons,
            "notes": "",
        }
        _save_result(row)

        attempts += 1
        if correct:
            score += 1

        print(f"Progress: {i+1}/{rounds}  |  Score: {score}/{attempts}\n")
        input("Press Enter to continue to next scenario...")

    # summary
    print("\n=== Simulator Summary ===")
    print(f"Scenarios attempted: {attempts}")
    print(f"Correct answers    : {score}")
    if attempts:
        pct = round((score/attempts)*100, 1)
        print(f"Accuracy           : {pct}%")
    print("\nQuick tips to identify phishing:")
    tips = [
        "1) Check the sender's full email address/domain carefully.",
        "2) Be suspicious of urgent calls-to-action and threats.",
        "3) Hover links (or inspect URLs) before clicking — look for odd domains.",
        "4) Look for spelling/grammar errors and unexpected attachments.",
        "5) Verify unexpected requests via official channels (call support).",
    ]
    for t in tips:
        print(t)
    print("\nResults saved to:", RESULT_CSV)
    print("=== End Simulator ===\n")


if __name__ == "__main__":
    run_phishing_simulator(n_rounds=5)
