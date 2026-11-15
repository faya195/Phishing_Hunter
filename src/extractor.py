import math
import os
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse
import pandas as pd

try:
    import whois
except ImportError:
    whois = None


def calculate_entropy(text: str) -> float:
    """Calculate Shannon Entropy to detect randomly generated domains (DGA)."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return round(entropy, 4)


def extract_lexical_features(url: str) -> dict:
    """Extract 16 statistical and structural features from a URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    suspicious_keywords = [
        "login", "verify", "update", "secure", "account",
        "banking", "confirm", "signin", "wallet", "free", "bonus"
    ]
    url_lower = url.lower()
    keyword_hits = sum(1 for word in suspicious_keywords if word in url_lower)

    digits_count = sum(c.isdigit() for c in url)
    has_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "count_dots": url.count("."),
        "count_hyphens": url.count("-"),
        "count_at": url.count("@"),
        "count_question": url.count("?"),
        "count_equals": url.count("="),
        "count_slashes": url.count("/"),
        "count_digits": digits_count,
        "digit_ratio": round(digits_count / max(len(url), 1), 4),
        "has_ip": has_ip,
        "is_https": 1 if parsed.scheme == "https" else 0,
        "suspicious_words": keyword_hits,
        "url_entropy": calculate_entropy(url),
        "hostname_entropy": calculate_entropy(hostname),
    }


def get_live_cyberops_iocs(url: str) -> dict:
    """Perform live WHOIS domain age and SSL certificate checks for real-time analysis."""
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    iocs = {"domain_age_days": -1, "ssl_valid": 0, "ssl_issuer": "Unknown"}

    # 1. WHOIS Domain Age Check
    if whois and domain:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                age = (datetime.now() - creation_date.replace(tzinfo=None)).days
                iocs["domain_age_days"] = max(age, 0)
        except Exception:
            pass

    # 2. SSL Certificate Validation
    if domain:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        iocs["ssl_valid"] = 1
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        iocs["ssl_issuer"] = issuer.get("organizationName", "Verified CA")
        except Exception:
            pass

    return iocs


if __name__ == "__main__":
    print("Loading clean URLs dataset...")
    df = pd.read_csv("data/processed/clean_urls.csv")

    print("Extracting lexical & entropy features...")
    features_list = [extract_lexical_features(u) for u in df["url"]]
    df_features = pd.DataFrame(features_list)
    df_features["label"] = df["label"]

    os.makedirs("data/processed", exist_ok=True)
    output_path = "data/processed/features_dataset.csv"
    df_features.to_csv(output_path, index=False)

    print(f"Done! Saved {df_features.shape[0]} rows and {df_features.shape[1]} columns to {output_path}")
    print("\nSample extracted features:")
    print(df_features.head(3))