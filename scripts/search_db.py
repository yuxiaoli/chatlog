import os
import sqlite3
import glob

db_files = glob.glob('../temp/results/wechat_work/Msg/*.db')
for db in db_files:
    try:
        conn = sqlite3.connect(db)
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        for (table,) in tables:
            try:
                cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
                col_names = [c[1] for c in cols]
                
                for col in col_names:
                    query = f"SELECT * FROM {table} WHERE CAST({col} AS TEXT) LIKE '%1994%'"
                    res = conn.execute(query).fetchall()
                    if res:
                        print(f"Found in {db} -> {table} -> {col}")
            except Exception as e:
                pass
    except Exception as e:
        pass
