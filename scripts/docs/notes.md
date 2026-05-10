View DuckDB tables
- favorites
- file_transfer

```powershell
.\scripts\migrate_favorites.ps1
.\scripts\migrate_file_transfer.ps1
```
```bash
uv run scripts/wechat_db.py --ui web/cli
```

Rename `scripts\fill_wechat_favorites.py` and support to pass in a database table name.
```bash
uv run scripts/get_content.py --table "favorites" -n 10
uv run scripts/get_content.py favorites file_transfer_messages -n 10
```

fill_wechat_favorites.py -> DuckDB tables
get_wechat_articles.go -> DuckDB tables
extract_github_urls.py -> DuckDB tables

Create another script `extract_github_urls.py` which support to pass in mutiple database table names and it shall process the content of each article and find all GitHub URLs in it and add a field to the table which shall be a list of strings (URLs).
```bash
uv run scripts/extract_github_urls.py favorites
```

wechat_db.py
--export
--ui web/cli
