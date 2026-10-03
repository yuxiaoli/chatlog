import sqlite3

def check_string_in_blob(blob, text):
    if blob is None: return False
    try:
        return text.encode('utf-8') in blob
    except:
        return False

conn = sqlite3.connect('../temp/results/wechat_work/Msg/MicroMsg.db')
conn.row_factory = sqlite3.Row

cursor = conn.execute("SELECT * FROM Contact WHERE Remark LIKE '%Anytime Fitness%' OR NickName LIKE '%比卡超%' OR Alias LIKE '%比卡超%'")
rows = cursor.fetchall()
for row in rows:
    print('--- Contact ---')
    for key in row.keys():
        val = row[key]
        if isinstance(val, bytes):
            print(f'{key}: <BLOB of size {len(val)}>')
            if check_string_in_blob(val, '碰巧遇到你'):
                print(f"    -> FOUND '碰巧遇到你' in {key}")
            if b'2025' in val or b'2025/9' in val:
                print(f"    -> FOUND '2025' in {key}")
        elif val:
            print(f'{key}: {val}')
            if isinstance(val, str) and '碰巧' in val:
                print(f"    -> FOUND '碰巧' in {key}")
