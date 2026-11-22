import os
import random
import time
import pandas as pd
import requests

HEADERS = {
    "User-Agent": "PhishingHunter-AcademicResearch/2.0 (Engineering Graduation Project)"
}

TARGET_PER_CLASS = 5000  # 5,000 Benign + 5,000 Malicious = 10,000 Total URLs


def fetch_github_cloud_apps(domain_keyword: str, max_pages: int = 3) -> list:
    """Fetch real legitimate developer apps hosted on Streamlit Cloud or GitHub Pages."""
    urls = []
    for page in range(1, max_pages + 1):
        try:
            api_url = (
                f"https://api.github.com/search/repositories"
                f"?q={domain_keyword}+in:homepage&per_page=100&page={page}"
            )
            resp = requests.get(api_url, headers=HEADERS, timeout=15)
            if resp.status_code == 200:
                items = resp.json().get("items", [])
                if not items:
                    break
                for item in items:
                    hp = (item.get("homepage") or "").strip().rstrip("/")
                    if hp.startswith("http") and domain_keyword in hp and len(hp) < 120:
                        urls.append(hp)
            else:
                break
            time.sleep(1.5)
        except Exception as e:
            print(f"[Warning] GitHub API page {page} skipped for {domain_keyword}: {e}")
            break
    return list(dict.fromkeys(urls))


def fetch_opendns_top_domains(limit: int = 2300) -> list:
    """Fetch verified legitimate top global domains from Cisco OpenDNS public list."""
    urls = []
    try:
        feed_url = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"
        resp = requests.get(feed_url, headers=HEADERS, timeout=20)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                domain = line.strip()
                if domain and not domain.startswith("#"):
                    prefix = "https://www." if domain.count(".") == 1 else "https://"
                    urls.append(f"{prefix}{domain}")
                if len(urls) >= limit:
                    break
    except Exception as e:
        print(f"[Warning] OpenDNS fetch error: {e}")
    return urls


def fetch_wikipedia_deep_urls(target_count: int = 2500) -> list:
    """Fetch thousands of legitimate deep-path URLs from Wikipedia in batches."""
    urls = []
    batches = (target_count // 500) + 1
    for _ in range(batches):
        try:
            api_url = (
                "https://en.wikipedia.org/w/api.php"
                "?action=query&list=random&rnnamespace=0&rnlimit=500&format=json"
            )
            resp = requests.get(api_url, headers=HEADERS, timeout=15)
            if resp.status_code == 200:
                pages = resp.json().get("query", {}).get("random", [])
                for page in pages:
                    title = page["title"].replace(" ", "_")
                    urls.append(f"https://en.wikipedia.org/wiki/{title}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[Warning] Wikipedia batch error: {e}")
    return list(dict.fromkeys(urls))[:target_count]


def fetch_streaming_lines(url: str, max_lines: int = 4000) -> list:
    """Stream lines from large threat feeds efficiently without high memory usage."""
    collected = []
    try:
        with requests.get(url, headers=HEADERS, stream=True, timeout=25) as resp:
            if resp.status_code == 200:
                for raw_line in resp.iter_lines(decode_unicode=True):
                    if not raw_line:
                        continue
                    line = raw_line.strip().rstrip("/")
                    if line.startswith("http") and not line.startswith("#"):
                        collected.append(line)
                    if len(collected) >= max_lines:
                        break
    except Exception as e:
        print(f"[Warning] Feed error ({url}): {e}")
    return collected


def fetch_malicious_urls(target_count: int = 5500) -> list:
    """Collect thousands of live phishing and malware URLs from multiple OSINT feeds."""
    cloud_phish = []
    general_malicious = []
    cloud_keywords = (
        "web.app", "github.io", "netlify.app", "vercel.app",
        "workers.dev", "pages.dev", "streamlit.app", "herokuapp.com",
    )

    # 1. OpenPhish Live Feed
    print("  -> Fetching OpenPhish live feed...")
    openphish_urls = fetch_streaming_lines("https://openphish.com/feed.txt", max_lines=1000)
    for u in openphish_urls:
        if any(ck in u.lower() for ck in cloud_keywords):
            cloud_phish.append(u)
        else:
            general_malicious.append(u)

    # 2. Phishing.Database Active Phishing Links (Thousands of verified phishing URLs)
    print("  -> Streaming Phishing.Database active feed...")
    phish_db_urls = fetch_streaming_lines(
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
        max_lines=4000,
    )
    for u in phish_db_urls:
        if any(ck in u.lower() for ck in cloud_keywords):
            cloud_phish.append(u)
        else:
            general_malicious.append(u)

    # 3. URLhaus Online & Recent Malware URLs
    print("  -> Fetching URLhaus online & recent malware feeds...")
    urlhaus_online = fetch_streaming_lines("https://urlhaus.abuse.ch/downloads/text_online/", max_lines=2500)
    urlhaus_recent = fetch_streaming_lines("https://urlhaus.abuse.ch/downloads/text_recent/", max_lines=2500)
    general_malicious.extend(urlhaus_online + urlhaus_recent)

    combined = list(dict.fromkeys(cloud_phish + general_malicious))
    print(f"  -> Cloud-hosted phishing found: {len(cloud_phish)} | Total unique malicious: {len(combined)}")
    return combined[:target_count]


def main():
    os.makedirs("data/raw", exist_ok=True)
    print(f"Starting large-scale dataset collection (Target: {TARGET_PER_CLASS * 2} balanced URLs)...")

    print("[1/4] Fetching legitimate cloud developer apps (Streamlit & GitHub Pages)...")
    streamlit_benign = fetch_github_cloud_apps("streamlit.app", max_pages=3)
    gh_pages_benign = fetch_github_cloud_apps("github.io", max_pages=3)
    print(f"  -> Collected {len(streamlit_benign)} Streamlit apps & {len(gh_pages_benign)} GitHub Pages sites.")

    print("[2/4] Fetching Cisco OpenDNS top legitimate domains...")
    opendns_benign = fetch_opendns_top_domains(limit=2300)
    print(f"  -> Collected {len(opendns_benign)} OpenDNS top domains.")

    print("[3/4] Fetching deep legitimate paths from Wikipedia...")
    wiki_benign = fetch_wikipedia_deep_urls(target_count=2500)
    print(f"  -> Collected {len(wiki_benign)} Wikipedia deep-path URLs.")

    all_benign = list(dict.fromkeys(streamlit_benign + gh_pages_benign + opendns_benign + wiki_benign))
    print(f"Total unique Benign URLs available: {len(all_benign)}")

    print("[4/4] Fetching live Phishing & Malware URLs...")
    all_malicious = fetch_malicious_urls(target_count=max(TARGET_PER_CLASS + 500, len(all_benign)))

    # Balance dataset strictly 50% Benign / 50% Malicious
    min_count = min(len(all_benign), len(all_malicious), TARGET_PER_CLASS)
    random.seed(42)
    benign_sample = random.sample(all_benign, min_count)
    malicious_sample = random.sample(all_malicious, min_count)

    df_benign = pd.DataFrame({"url": benign_sample, "label": 0})
    df_malicious = pd.DataFrame({"url": malicious_sample, "label": 1})

    df_final = pd.concat([df_benign, df_malicious], ignore_index=True).sample(frac=1, random_state=42)
    output_path = "data/raw/raw_urls.csv"
    df_final.to_csv(output_path, index=False)
    print(f"\nSUCCESS: Saved {len(df_final)} balanced URLs ({min_count} benign + {min_count} malicious) to {output_path}")


if __name__ == "__main__":
    main()