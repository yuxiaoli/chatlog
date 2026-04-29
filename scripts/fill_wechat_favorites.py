# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests",
#     "tqdm",
# ]
# ///

import argparse
import sys
import json
import requests
from tqdm import tqdm
from pathlib import Path

PROXY_URL = "https://proxy.cf-io.workers.dev/"

def extract_article_text(target_url: str) -> str:
    """Extracts article text from WeChat URL using the proxy worker."""
    params = {
        "url": target_url,
        "extractText": "true"
    }
    try:
        response = requests.get(PROXY_URL, params=params, timeout=30)
        response.raise_for_status()
        response.encoding = 'utf-8'  # Explicitly set UTF-8 encoding
        return response.text
    except requests.exceptions.RequestException as e:
        # Print error but don't exit so we can continue with other articles
        tqdm.write(f"❌ Error extracting article {target_url}: {e}")
        return ""

def main():
    parser = argparse.ArgumentParser(
        description="Fill 'content' field in wechat_favorites.json using WeChat article proxy."
    )
    parser.add_argument(
        "-n", "--number",
        type=int,
        default=None,
        help="Number of articles to process (default: all)"
    )
    
    args = parser.parse_args()
    
    # Path to the favorites JSON file
    json_path = Path("temp/results/wechat_favorites.json")
    if not json_path.exists():
        print(f"❌ Error: File not found at {json_path}", file=sys.stderr)
        sys.exit(1)
        
    print(f"Loading data from {json_path}...")
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    # Find items that need filling (content is empty or missing)
    items_to_fill = [item for item in data if not item.get("content")]
    
    if not items_to_fill:
        print("✅ All items already have content.")
        return
        
    if args.number is not None:
        limit = min(args.number, len(items_to_fill))
        process_items = items_to_fill[:limit]
    else:
        limit = len(items_to_fill)
        process_items = items_to_fill
    
    print(f"Found {len(items_to_fill)} articles without content.")
    print(f"Processing {limit} articles...")
    
    # Process items with progress bar
    success_count = 0
    for item in tqdm(process_items, desc="Extracting articles", unit="article"):
        url = item.get("url")
        if url:
            content = extract_article_text(url)
            if content:
                item["content"] = content
                success_count += 1
                
    # Save back to json if any items were updated
    if success_count > 0:
        print(f"Saving {success_count} updated articles to {json_path}...")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print("✅ Successfully updated the JSON file.")
    else:
        print("⚠️ No articles were successfully extracted.")

if __name__ == "__main__":
    main()
