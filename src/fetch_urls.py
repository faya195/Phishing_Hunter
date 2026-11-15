import io
import os
import random
import zipfile
import pandas as pd
import requests

os.makedirs("data/raw", exist_ok=True)
browser_headers = {"User-Agent": "Mozilla/5.0"}
wiki_headers = {"User-Agent": "PhishingHunterStudentProject/1.0 (educational-ml-research)"}
phish_urls = set()

print("1. Fetching malicious URLs...")
try:
    r1 = requests.get("https://openphish.com/feed.txt", headers=browser_headers, timeout=15)
    if r1.status_code == 200:
        phish_urls.update(r1.text.strip().splitlines())
except Exception as e:
    print("OpenPhish note:", e)

try:
    r2 = requests.get("https://urlhaus.abuse.ch/downloads/text_recent/", headers=browser_headers, timeout=15)
    if r2.status_code == 200:
        lines = [l.strip() for l in r2.text.splitlines() if l.strip() and not l.startswith("#")]
        phish_urls.update(lines)
except Exception as e:
    print("URLhaus note:", e)

malicious_list = list(phish_urls)[:1000]
df_malicious = pd.DataFrame({"url": malicious_list, "label": 1})
print(f"Collected {len(df_malicious)} malicious URLs.")

print("2. Fetching diverse benign URLs (Root domains + Long article/page paths)...")
resp_tranco = requests.get("https://tranco-list.eu/top-1m.csv.zip", headers=browser_headers, timeout=20)
with zipfile.ZipFile(io.BytesIO(resp_tranco.content)) as z:
    df_tranco = pd.read_csv(z.open(z.namelist()[0]), names=["rank", "domain"])

top_domains = df_tranco["domain"].dropna().tolist()
half_count = len(df_malicious) // 2

# Part A: Half root domains
benign_urls = ["https://" + d for d in top_domains[:half_count]]

# Part B: Half long benign URLs (Wikipedia API + Realistic paths fallback)
needed_long = len(df_malicious) - len(benign_urls)
try:
    wiki_api = f"https://en.wikipedia.org/w/api.php?action=query&list=random&rnnamespace=0&rnlimit={min(needed_long, 500)}&format=json"
    r_wiki = requests.get(wiki_api, headers=wiki_headers, timeout=15)
    if r_wiki.status_code == 200:
        for item in r_wiki.json()["query"]["random"]:
            slug = item["title"].replace(" ", "_")
            benign_urls.append(f"https://en.wikipedia.org/wiki/{slug}")
except Exception:
    pass

# Fill any remaining count with realistic long paths on trusted Tranco domains
realistic_paths = [
    "/about-us/company-overview",
    "/blog/2026/11/security-and-technology-update",
    "/docs/v2/getting-started/installation-guide",
    "/products/category/electronics/item-48291",
    "/news/world/science-and-innovation-report",
    "/help/support/frequently-asked-questions",
    "/research/publications/annual-review-2026",
]
idx = half_count
while len(benign_urls) < len(df_malicious):
    domain = top_domains[idx % len(top_domains)]
    path = random.choice(realistic_paths)
    benign_urls.append(f"https://{domain}{path}")
    idx += 1

df_benign = pd.DataFrame({"url": benign_urls[:len(df_malicious)], "label": 0})
print(f"Collected {len(df_benign)} diverse benign URLs.")

# Merge and save
df_raw = pd.concat([df_malicious, df_benign], ignore_index=True)
df_raw.to_csv("data/raw/raw_urls.csv", index=False)
print(f"Done! Total saved URLs: {len(df_raw)} in data/raw/raw_urls.csv")