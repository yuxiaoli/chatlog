# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "requests",
#     "tqdm",
#     "duckdb",
# ]
# ///

import argparse
import sys
import requests
import duckdb
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
        description="Get and fill content field in DuckDB tables using WeChat article proxy."
    )
    parser.add_argument(
        "tables",
        nargs="+",
        type=str,
        help="Target table names in DuckDB (e.g., favorites file_transfer_messages)"
    )
    parser.add_argument(
        "-n", "--number",
        type=int,
        default=None,
        help="Number of articles to process per table (default: all)"
    )
    
    args = parser.parse_args()
    
    # Pre-defined configurations for known tables
    TABLE_CONFIGS = {
        "favorites": {
            "id_col": "FavLocalID",
            "url_col": "URL",
            "content_col": "Content"
        },
        "file_transfer_messages": {
            "id_col": "MsgSvrID",
            "url_col": "Url",  # Note: The JSON schema outputs "Url", not "URL"
            "content_col": "StrContent"
        }
    }
    
    db_path = Path("temp/results/chatlog.duckdb")
    if not db_path.exists():
        print(f"❌ Error: Database not found at {db_path}", file=sys.stderr)
        sys.exit(1)
        
    print(f"Connecting to DuckDB at {db_path}...")
    conn = duckdb.connect(str(db_path))
    
    total_success = 0
    
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
            url_col = config["url_col"]
            content_col = config["content_col"]
        else:
            print(f"⚠️ Warning: Unknown table '{table}'. Assuming standard columns: FavLocalID, URL, Content.")
            id_col = "FavLocalID"
            url_col = "URL"
            content_col = "Content"
            
        try:
            # Find items that need filling (content is empty or missing)
            query = f"SELECT {id_col}, {url_col} FROM {table} WHERE ({content_col} IS NULL OR {content_col} = '') AND {url_col} IS NOT NULL AND {url_col} != ''"
            items_to_fill = conn.execute(query).fetchall()
            
            if not items_to_fill:
                print(f"✅ All items in '{table}' already have content or lack URLs.")
                continue
                
            if args.number is not None:
                limit = min(args.number, len(items_to_fill))
                process_items = items_to_fill[:limit]
            else:
                limit = len(items_to_fill)
                process_items = items_to_fill
            
            print(f"Found {len(items_to_fill)} articles without content in '{table}'.")
            print(f"Processing {limit} articles...")
            
            # Process items with progress bar
            success_count = 0
            for item_id, url in tqdm(process_items, desc=f"Extracting for {table}", unit="article"):
                if url:
                    content = extract_article_text(url)
                    if content:
                        # Update DuckDB
                        conn.execute(f"UPDATE {table} SET {content_col} = ? WHERE {id_col} = ?", (content, item_id))
                        success_count += 1
            
            total_success += success_count
            print(f"Updated {success_count} articles in '{table}'.")
            
        except Exception as e:
            print(f"❌ Error processing table '{table}': {e}")
            
    if total_success > 0:
        print(f"\n✅ Successfully updated a total of {total_success} articles across all tables.")
        print("💡 Run 'go run scripts/export_json.go' to regenerate the JSON and MD files.")
    else:
        print("\n⚠️ No articles were successfully extracted.")
        
    conn.close()

if __name__ == "__main__":
    main()
