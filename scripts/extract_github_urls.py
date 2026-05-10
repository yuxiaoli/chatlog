# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "duckdb",
#     "tqdm",
# ]
# ///

import argparse
import sys
import re
import json
from tqdm import tqdm
from pathlib import Path

# DB path relative to where the script is executed
DB_PATH = Path(__file__).parent.parent / "temp/results/chatlog.duckdb"

# Pre-defined configurations for known tables
TABLE_CONFIGS = {
    "favorites": {
        "id_col": "FavLocalID",
        "content_col": "Content",
        "url_array_col": "GithubUrls"
    },
    "file_transfer_messages": {
        "id_col": "MsgSvrID",
        "content_col": "StrContent",
        "url_array_col": "GithubUrls"
    }
}

# Regex to match Github URLs
# Matches https://github.com/user/repo, ignoring trailing punctuation usually found in markdown or text
GITHUB_URL_PATTERN = re.compile(r'https?://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/?')

def extract_github_urls(text: str) -> list[str]:
    """Extracts all unique GitHub URLs from a given text string."""
    if not text:
        return []
    urls = GITHUB_URL_PATTERN.findall(text)
    
    # Clean up trailing punctuation that might get caught
    cleaned_urls = []
    for url in urls:
        url = url.rstrip('.,;)"\'')
        if url not in cleaned_urls:
            cleaned_urls.append(url)
            
    return cleaned_urls

def main():
    parser = argparse.ArgumentParser(
        description="Extract GitHub URLs from content and add them to a DuckDB table."
    )
    parser.add_argument(
        "tables",
        nargs="+",
        type=str,
        help="Target table names in DuckDB (e.g., favorites file_transfer_messages)"
    )
    
    args = parser.parse_args()
    
    if not DB_PATH.exists():
        print(f"❌ Error: Database not found at {DB_PATH}")
        sys.exit(1)
        
    print(f"Connecting to DuckDB at {DB_PATH}...")
    import duckdb
    conn = duckdb.connect(str(DB_PATH))
    
    total_urls_found = 0
    total_articles_updated = 0
    
    for table in args.tables:
        print(f"\n--- Processing table: {table} ---")
        
        # Check if table exists in DuckDB
        table_exists = conn.execute(f"SELECT COUNT(*) FROM information_schema.tables WHERE table_name = '{table}'").fetchone()[0] > 0
        if not table_exists:
            print(f"⚠️ Warning: Table '{table}' does not exist in the database. Skipping.")
            continue
            
        # Get column configuration
        if table in TABLE_CONFIGS:
            config = TABLE_CONFIGS[table]
            id_col = config["id_col"]
            content_col = config["content_col"]
            url_array_col = config["url_array_col"]
        else:
            print(f"⚠️ Warning: Unknown table '{table}'. Assuming standard columns: FavLocalID, Content, GithubUrls.")
            id_col = "FavLocalID"
            content_col = "Content"
            url_array_col = "GithubUrls"
            
        try:
            # Check if the target column exists, if not, add it
            columns_query = conn.execute(f"PRAGMA table_info('{table}')").fetchall()
            column_names = [col[1] for col in columns_query]
            
            if url_array_col not in column_names:
                print(f"Adding '{url_array_col}' column to '{table}'...")
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {url_array_col} TEXT")
            
            # Fetch all rows that have content
            query = f"SELECT {id_col}, {content_col} FROM {table} WHERE {content_col} IS NOT NULL AND {content_col} != ''"
            items = conn.execute(query).fetchall()
            
            if not items:
                print(f"No content found in '{table}'.")
                continue
                
            print(f"Analyzing {len(items)} rows in '{table}' for GitHub URLs...")
            
            update_count = 0
            urls_found_in_table = 0
            
            for item_id, content in tqdm(items, desc=f"Scanning {table}", unit="row"):
                urls = extract_github_urls(content)
                if urls:
                    urls_json = json.dumps(urls)
                    conn.execute(f"UPDATE {table} SET {url_array_col} = ? WHERE {id_col} = ?", (urls_json, item_id))
                    update_count += 1
                    urls_found_in_table += len(urls)
            
            total_articles_updated += update_count
            total_urls_found += urls_found_in_table
            
            print(f"Updated {update_count} rows with {urls_found_in_table} GitHub URLs in '{table}'.")
            
        except Exception as e:
            print(f"❌ Error processing table '{table}': {e}")
            
    print(f"\n✅ Finished processing. Found {total_urls_found} total GitHub URLs across {total_articles_updated} rows.")
    conn.close()

if __name__ == "__main__":
    main()
