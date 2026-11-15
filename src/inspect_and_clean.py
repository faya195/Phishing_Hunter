import os
import pandas as pd

os.makedirs("data/processed", exist_ok=True)

# 1. Load raw URLs dataset
df_urls = pd.read_csv("data/raw/raw_urls.csv")

print("--- 1. Dataset Info & Missing Values ---")
print(df_urls.info())
print(df_urls.isnull().sum())

# Remove empty rows and extra spaces
df_urls.dropna(subset=["url", "label"], inplace=True)
df_urls["url"] = df_urls["url"].str.strip()

print("\n--- 2. Checking Duplicates ---")
duplicates_count = df_urls.duplicated(subset=["url"]).sum()
print(f"Duplicate URLs found: {duplicates_count}")
df_urls.drop_duplicates(subset=["url"], inplace=True)

print("\n--- 3. Class Balance (%) ---")
print(df_urls["label"].value_counts(normalize=True) * 100)

print("\n--- 4. Protocol Sanity Check ---")
df_urls = df_urls[df_urls["url"].str.startswith(("http://", "https://"))]

# Shuffle dataset randomly and save clean file
df_urls = df_urls.sample(frac=1, random_state=42).reset_index(drop=True)
df_urls.to_csv("data/processed/clean_urls.csv", index=False)

print(f"\nDone! Final clean URLs count: {len(df_urls)}")
print("\nSample rows:")
print(df_urls.head(5))