import std/strformat
import std/strutils
import std/logging

import ndb/sqlite

type
  Patch* = tuple
    name: string
    sqls: seq[string]

proc upgradeSchema*(db:DbConn, patches:openArray[Patch]) =
    ## Apply database patches to this file
    # See what patches have already been applied
    db.exec(sql"""
    CREATE TABLE IF NOT EXISTS _schema_version (
        id INTEGER PRIMARY KEY,
        created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        name TEXT UNIQUE
    )""")
    var applied:seq[string]
    for row in db.getAllRows(sql"SELECT name FROM _schema_version"):
        applied.add(row[0].s)
    if applied.len > 0:
        logging.debug &"(dbpatch) existing patches: {applied}"
    
    # Apply patches
    for patch in patches:
        if patch.name in applied:
            continue
        logging.info &"(dbpatch) applying patch: {patch.name}"
        db.exec(sql"BEGIN")
        try:
            for statement in patch.sqls:
              db.exec(sql(statement))
            db.exec(sql"INSERT INTO _schema_version (name) VALUES (?)", patch.name)
            db.exec(sql"COMMIT")
        except:
            logging.error &"(dbpatch) error applying patch {patch.name}: {getCurrentExceptionMsg()}"
            db.exec(sql"ROLLBACK")
            raise
