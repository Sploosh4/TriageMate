---
name: dual-database-ddl
description: Enforce SQLite + PostgreSQL dual DDL pattern for every schema change in database.py
---

## Rule
Every schema change in `database.py` requires entries in **both** `_init_db_sqlite()` and `_init_db_pg()`.

## Steps
1. Open `backend/database.py`
2. Locate the `vulnerabilities` table in `_init_db_sqlite()`
3. Add your new column there with SQLite-compatible type
4. Locate the identical table in `_init_db_pg()`
5. Add the matching column there with PostgreSQL-compatible type
6. Repeat for `resolved_vulnerabilities` table in both methods
7. Also add to the migration helper list at the bottom of each method if this is a post-MVP column

## Type mapping
| SQLite     | PostgreSQL          |
|------------|---------------------|
| INTEGER    | SERIAL (PK) / INTEGER |
| REAL       | REAL                |
| TEXT       | TEXT / VARCHAR(n)   |
| BOOLEAN    | BOOLEAN             |
| TIMESTAMP  | TIMESTAMP           |

## Checklist
- [ ] Column added to `_init_db_sqlite()` → `vulnerabilities`
- [ ] Column added to `_init_db_pg()` → `vulnerabilities`
- [ ] Column added to `_init_db_sqlite()` → `resolved_vulnerabilities`
- [ ] Column added to `_init_db_pg()` → `resolved_vulnerabilities`
- [ ] Types match across both dialects
