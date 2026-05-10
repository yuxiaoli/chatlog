# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "duckdb",
#     "pandas",
#     "numpy",
# ]
# ///

import sys
import duckdb
import argparse
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Load JSON data into DuckDB.")
    parser.add_argument("db_path", help="Path to the DuckDB database file")
    parser.add_argument("json_path", help="Path to the JSON file to load")
    parser.add_argument("table_name", help="Target table name in DuckDB")
    parser.add_argument("--schema-cast", help="Optional SQL cast operations for columns (e.g. 'CAST(Tags AS VARCHAR) as Tags')")
    
    args = parser.parse_args()
    
    db_path = Path(args.db_path)
    json_path = Path(args.json_path)
    
    if not json_path.exists():
        print(f"❌ Error: JSON file not found at {json_path}")
        sys.exit(1)
        
    print(f"Connecting to DuckDB at {db_path}...")
    
    # Ensure directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = duckdb.connect(str(db_path))
    
    try:
        # For read_json_auto we need forward slashes for Windows paths
        clean_json_path = str(json_path.absolute()).replace("\\", "/")
        
        print(f"Loading data into table '{args.table_name}'...")
        
        # Check if table exists to potentially drop it
        conn.execute(f"DROP TABLE IF EXISTS {args.table_name}")
        
        # First check if the file contains only 'null'
        with open(clean_json_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content == 'null' or not content:
                print(f"Warning: JSON file {clean_json_path} is empty or null. Creating empty table.")
                # Create empty table with minimal schema if we don't know it
                if args.schema_cast:
                    # Very basic parser to extract column names from schema_cast for empty table
                    cols = [c.split('AS')[-1].strip() for c in args.schema_cast.split(',')]
                    col_defs = ", ".join([f"{c} VARCHAR" for c in cols])
                    conn.execute(f"CREATE TABLE {args.table_name} ({col_defs})")
                else:
                    # Fallback to an empty generic table
                    conn.execute(f"CREATE TABLE {args.table_name} (id INTEGER)")
                conn.close()
                return

        # Determine the columns that actually exist in the JSON file
        try:
            # First detect if the JSON is actually valid and what columns it has
            detect_query = f"SELECT * FROM read_json_auto('{clean_json_path}', maximum_object_size=33554432, format='auto') LIMIT 1"
            detect_result = conn.execute(detect_query).fetchdf()
            actual_columns = list(detect_result.columns)
            print(f"Detected JSON columns: {actual_columns}")
            
            if args.schema_cast:
                # If 'Type' is requested but 'type' exists, handle case-insensitivity manually
                select_clause = args.schema_cast
                # Handle special Type keyword which is reserved in some SQL dialects
                if '"Type"' in select_clause and 'Type' not in actual_columns and 'type' in actual_columns:
                    select_clause = select_clause.replace('"Type"', 'type AS "Type"')
                elif 'Type' in select_clause and 'Type' not in actual_columns and 'type' in actual_columns:
                    select_clause = select_clause.replace('Type', 'type AS Type')
                
                query = f"CREATE TABLE {args.table_name} AS SELECT {select_clause} FROM read_json_auto('{clean_json_path}', maximum_object_size=33554432, format='auto')"
            else:
                query = f"CREATE TABLE {args.table_name} AS SELECT * FROM read_json_auto('{clean_json_path}', maximum_object_size=33554432, format='auto')"
        except Exception as detect_err:
            print(f"Warning: Column detection failed ({detect_err}). Proceeding with standard load.")
            if args.schema_cast:
                query = f"CREATE TABLE {args.table_name} AS SELECT {args.schema_cast} FROM read_json_auto('{clean_json_path}', maximum_object_size=33554432, format='auto')"
            else:
                query = f"CREATE TABLE {args.table_name} AS SELECT * FROM read_json_auto('{clean_json_path}', maximum_object_size=33554432, format='auto')"
            
        conn.execute(query)
        
        # Verify row count
        count = conn.execute(f"SELECT count(*) FROM {args.table_name}").fetchone()[0]
        print(f"✅ Successfully loaded {count} rows into {args.table_name}.")
        
    except Exception as e:
        print(f"❌ Error loading data: {e}")
        sys.exit(1)
    finally:
        conn.close()

if __name__ == "__main__":
    main()
