# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "duckdb",
# ]
# ///

import argparse
import sys
import subprocess
from pathlib import Path

# DB paths relative to where the script is executed
DB_PATH = Path(__file__).parent.parent / "temp/results/chatlog.duckdb"

def export_data(table_names=None):
    import duckdb
    if not DB_PATH.exists():
        print(f"❌ Error: Database not found at {DB_PATH}")
        sys.exit(1)
        
    print(f"Connecting to {DB_PATH} for export...")
    conn = duckdb.connect(str(DB_PATH), read_only=True)
    
    available_tables = [row[0] for row in conn.execute("SHOW TABLES").fetchall()]
    
    if table_names:
        tables = [t for t in table_names if t in available_tables]
        missing = set(table_names) - set(available_tables)
        if missing:
            print(f"⚠️ Warning: Following tables not found: {', '.join(missing)}")
        if not tables:
            print("❌ Error: None of the specified tables were found.")
            sys.exit(1)
    else:
        tables = available_tables
    
    export_dir = Path(__file__).parent.parent / "temp/results/exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    
    for table in tables:
        json_path = export_dir / f"{table}.json"
        
        print(f"Exporting {table} to JSON...")
        conn.execute(f"COPY {table} TO '{json_path}' (FORMAT JSON, ARRAY TRUE)")
        
    print(f"✅ Export completed successfully. Files saved to {export_dir}")
    conn.close()

def run_cli():
    if not DB_PATH.exists():
        print(f"❌ Error: Database not found at {DB_PATH}")
        sys.exit(1)
        
    print(f"Launching DuckDB CLI via python duckdb module for {DB_PATH}...")
    import duckdb
    
    # We can launch the terminal CLI interactive mode directly from the python module using `.exe()` equivalent workaround
    # or by delegating to duckdb python module's internal shell. 
    # Unfortunately duckdb python module doesn't expose the `-ui` TUI directly.
    # However, since the user wants the CLI experience without installing the global executable, 
    # we can use the bundled python CLI logic if possible, or gracefully failback to instructions.
    
    # Since duckdb python doesn't bundle the interactive TUI shell natively,
    # let's write a small interactive prompt to query tables if they can't install the duckdb CLI
    print("\n--- DuckDB Interactive Shell (Python Fallback) ---")
    print("Since duckdb CLI is not installed globally, launching a minimal query shell.")
    print("Type 'exit' or 'quit' to close. Type 'tables' to list tables.\n")
    
    conn = duckdb.connect(str(DB_PATH))
    try:
        while True:
            try:
                query = input("duckdb> ")
                if query.lower() in ['exit', 'quit']:
                    break
                if query.lower() == 'tables':
                    query = "SHOW TABLES"
                if not query.strip():
                    continue
                    
                result = conn.execute(query).fetchdf()
                print(result)
            except Exception as e:
                print(f"Error: {e}")
            except KeyboardInterrupt:
                break
    finally:
        conn.close()

def run_web_ui():
    if not DB_PATH.exists():
        print(f"❌ Error: Database not found at {DB_PATH}")
        sys.exit(1)
        
    print(f"Launching DuckDB built-in Web UI...")
    import duckdb
    import time
    
    conn = duckdb.connect(str(DB_PATH))
    try:
        print("Installing/Loading 'ui' extension...")
        conn.execute("INSTALL ui;")
        conn.execute("LOAD ui;")
        
        print("Starting UI server... (A browser window should open automatically)")
        conn.execute("CALL start_ui();")
        
        print("\nUI is running. Press Ctrl+C to stop the server and exit.")
        while True:
            time.sleep(1)
            
    except Exception as e:
        print(f"❌ Error running DuckDB UI: {e}")
    except KeyboardInterrupt:
        print("\nStopping UI server...")
        try:
            conn.execute("CALL stop_ui_server();")
        except:
            pass
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="WeChat DuckDB management script.")
    parser.add_argument("--export", nargs="*", metavar="TABLE", help="Export specified tables to JSON (exports all if no tables provided)")
    parser.add_argument("--ui", choices=["cli", "web"], help="Launch DuckDB interface (cli: interactive shell, web: Streamlit dashboard)")
    
    args = parser.parse_args()
    
    if args.export is None and not args.ui:
        parser.print_help()
        sys.exit(1)
        
    if args.export is not None:
        export_data(args.export if len(args.export) > 0 else None)
        
    if args.ui == "cli":
        run_cli()
        
    elif args.ui == "web":
        run_web_ui()

if __name__ == "__main__":
    main()
