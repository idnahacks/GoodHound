from sys import platform, exit
from pathlib import Path
from datetime import datetime
import logging
import os

def getlistindex(lst, key, value):
    for index, dic in enumerate(lst):
        if dic[key] == value:
            return index

def getos():
    os = platform
    return os

def banner():
    print("""   ______                ____  __                      __""")
    print("""  / ____/___  ____  ____/ / / / /___  __  ______  ____/ /""")
    print(""" / / __/ __ \/ __ \/ __  / /_/ / __ \/ / / / __ \/ __  / """)
    print("""/ /_/ / /_/ / /_/ / /_/ / __  / /_/ / /_/ / / / / /_/ /  """)
    print(  "\____/\____/\____/\__,_/_/ /_/\____/\__,_/_/ /_/\__,_/   """)

def checkifoutfileexists(file):
        while Path(file).exists():
            stem = Path(file).stem
            newfile = str(Path(file).with_stem(stem + '-' + (datetime.now()).strftime("%Y-%m-%d-%H-%M")))
            file = newfile
        return file

def checkoutdir(path):
    """Check if the user input output path exists and is a directory and creates the file path if needed."""
    if Path(path).exists():
        if not Path(path).is_dir():
            logging.error('Selected output path is not a directory')
            exit(1)
    else:
        os.makedirs(path, exist_ok=True)

def checkdbfileexists(sqlpath):
    """Looks at the provided sql-path argument and determines whether to create a new db or update an existing one."""
    if Path(sqlpath).exists():
        if Path(sqlpath).is_file():
            dbfile = sqlpath
        else:
            dbfile = sqlpath + os.sep + "goodhound.db"
    else:
        os.makedirs(sqlpath, exist_ok=True)
        dbfile = sqlpath + os.sep + "goodhound.db"
    return dbfile