from goodhound import neodb, ghutils
from sqlite3.dbapi2 import Error
import sqlite3
from pathlib import Path
import os

def db(results, graph, args):
    """Inserts all of the attack paths found into a SQLite database"""
    if not args.db_skip:
        table_sql = """CREATE TABLE IF NOT EXISTS paths (
    	uid TEXT PRIMARY KEY,
    	startnode TEXT NOT NULL,
    	num_users INTEGER NOT NULL,
    	percentage REAL NOT NULL,
    	hops INTEGER NOT NULL,
    	cost INTEGER NOT NULL,
        riskscore REAL NOT NULL,
        fullpath TEXT NOT NULL,
        query TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
    	last_seen INTEGER NOT NULL);"""
        conn = None
        dbpath = ghutils.checkdbfileexists(args.sql_path)
        try:
            conn = sqlite3.connect(dbpath)
            c = conn.cursor()
            c.execute(table_sql)
            scandate, scandatenice = neodb.getscandate(graph)
            seen_before=0
            new_path=0
            for r in results:
                insertvalues = (r[8],r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],scandate,scandate,)
                insertpath_sql = 'INSERT INTO paths VALUES (?,?,?,?,?,?,?,?,?,?,?)'
                # Determines if the path has been previously logged in the database using the UID and updates the last_seen field
                updatevalues = {"last_seen":scandate, "uid":r[8]}
                updatepath_sql = 'UPDATE paths SET last_seen=:last_seen WHERE uid=:uid'
                # Determines if the path has not been seen before based on the UID and inserts it into the database
                c.execute("SELECT count(*) FROM paths WHERE uid = ?", (r[8],))
                data = c.fetchone()[0]
                if data==0:
                    c.execute(insertpath_sql, insertvalues)
                    new_path += 1
                else:
                    # Catch to stop accidentally overwriting the database with older data
                    c.execute("SELECT last_seen from paths WHERE uid = ?", (r[8],))
                    pathlastseen = int(c.fetchone()[0])
                    if pathlastseen < scandate:
                        c.execute(updatepath_sql, updatevalues)
                    # update first_seen if an older dataset is loaded in
                    c.execute("SELECT first_seen from paths WHERE uid = ?", (r[8],))
                    pathfirstseen = int(c.fetchone()[0])
                    if pathfirstseen > scandate:
                        c.execute("UPDATE paths SET first_seen=:first_seen WHERE uid=:uid", {"first_seen":scandate, "uid":r[8]})
                    seen_before += 1
            conn.commit()
        except Error as e:
            print(e)
        finally:
            if conn:
                conn.close()
    else:
        new_path = 0
        seen_before = 0
        scandate, scandatenice = neodb.getscandate(graph)
    return new_path, seen_before, scandatenice