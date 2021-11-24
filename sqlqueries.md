# Goodhound SQLITE queries
## Connect to DB
```
sqlite3.exe db\goodhound.db
```

## Get paths not seen in over 90 days
```sql
select * from paths where date(last_seen, 'unixepoch') < date('now', '-90 days');
```

## See number of paths containing a section of paths, useful for looking at the Common Node pinch point
```sql
select count(*) from paths where fullpath like'%ReadLAPSPassword -> SERVER%.DOMAIN.LOCAL%';
```

## See bloodhound queries for paths containing a key starting group and scan time
```sql
select query from paths where groupname = 'GROUP1@DOMAIN.LOCAL' and datetime(last_seen, 'unixepoch') = '2021-10-28 05:15:22';
```

## Close DB connection
```sql
.quit
```