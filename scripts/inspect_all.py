import sqlite3

conn = sqlite3.connect('../temp/results/wechat_work/Msg/MicroMsg.db')
conn.row_factory = sqlite3.Row
cursor = conn.execute("SELECT * FROM Contact WHERE UserName = 'wxid_k1jztb2jlxbf22'")
row = cursor.fetchone()

if row:
    print('--- Database Columns ---')
    for key in row.keys():
        if key != 'ExtraBuf':
            print(f'{key}: {row[key]}')
