# Copyright (c) One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/base64
import std/logging
import std/options
import std/strutils
import std/strformat
import std/tables
import std/times

import lowdb/sqlite
import libsodium/sodium

import ./objs; export objs

const LOG_COMMS = not defined(release)
const TESTMODE = defined(testmode) and not defined(release)

type
  KeyPair* = tuple
    pk: PublicKey
    sk: SecretKey

  Relay*[T] = object
    db*: DbConn
    clients: TableRef[PublicKey, RelayConnection[T]]
  
  RelayConnection*[T] = ref object
    sender*: T
    pubkey*: PublicKey ## The authenticated pubkey
    challenge: string

when TESTMODE:
  var TIME_SKEW = 0
  proc skewTime*(seconds: int) =
    TIME_SKEW += seconds
  proc skewTime*(dur: Duration) =
    TIME_SKEW += dur.inSeconds()
  proc resetSkew*() =
    TIME_SKEW = 0

#-------------------------------------------------------------------
# Database
#-------------------------------------------------------------------
func strval*(dbval: sqlite.DbValue): string =
  case dbval.kind
  of dvkString:
    dbval.s
  of dvkNull:
    ""
  else:
    raise ValueError.newException("Can't get string from " & $dbval.kind)

proc toDB*(p: PublicKey): string =
  base64.encode(p.string)

proc fromDB*(t: typedesc[PublicKey], v: string): PublicKey =
  base64.decode(v).PublicKey

proc fromDB*(t: typedesc[PublicKey], v: DbBlob): PublicKey =
  base64.decode(v.string).PublicKey

template patch(db: untyped, applied: seq[string], name: string, body: untyped): untyped =
  block:
    if name notin applied:
      info name, " - applying..."
      db.exec(sql"BEGIN")
      try:
        body
        db.exec(sql"INSERT INTO _schema_patches (name) VALUES (?)", name)
        db.exec(sql"COMMIT")
      except:
        error name, " - error applying patch: " & getCurrentExceptionMsg()
        db.exec(sql"ROLLBACK")
        raise
    else:
      debug name, " - applied"

proc updateSchema*(db: DbConn) =
  ## Upgrade the schema
  db.exec(sql"""CREATE TABLE IF NOT EXISTS _schema_patches (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )""")
  
  var applied: seq[string]
  for row in db.getAllRows(sql"SELECT name FROM _schema_patches"):
    applied.add(row[0].strval)
  
  info "Already applied patches: ", applied.join(",")

  db.patch(applied, "initial"):
    # note
    db.exec(sql"""CREATE TABLE note (
      topic TEXT PRIMARY KEY,
      created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      data BLOB DEFAULT ''
    )""")
    db.exec(sql"CREATE INDEX note_created ON note(created)")
    
    # message
    db.exec(sql"""CREATE TABLE message (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      src TEXT NOT NULL,
      data BLOB NOT NULL
    )""")
    db.exec(sql"CREATE INDEX message_created ON message(created)")
    
    # message_route
    db.exec(sql"""CREATE TABLE message_route (
      id INTEGER PRIMARY KEY,
      message_id INTEGER REFERENCES message(id) ON DELETE CASCADE,
      dst TEXT NOT NULL
    )""")
    db.exec(sql"CREATE INDEX message_route_dst ON message_route(dst)")
    
    # message_dst
    db.exec(sql"""CREATE VIEW message_dst AS
    SELECT
      m.id,
      m.created,
      m.src,
      r.dst,
      m.data,
      r.id AS route_id
    FROM
      message_route AS r
      JOIN message AS m
        ON m.id = r.message_id
    """)

    # auto-delete message orphans
    db.exec(sql"""
      CREATE TRIGGER IF NOT EXISTS delete_orphaned_message
      AFTER DELETE ON message_route
      FOR EACH ROW
      BEGIN
          DELETE FROM message
          WHERE id = OLD.message_id
            AND NOT EXISTS (
                SELECT 1 FROM message_route WHERE message_id = OLD.message_id
            );
      END;
    """)
    
    # known_pubkey
    db.exec(sql"""CREATE TABLE known_pubkey (
      pubkey TEXT PRIMARY KEY,
      last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    db.exec(sql"CREATE INDEX known_pubkey_last_seen ON known_pubkey(last_seen)")
  
  #----------- in-memory stuff
  db.exec(sql"""CREATE TEMPORARY TABLE note_sub (
    topic TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL
  )""")
  db.exec(sql"CREATE INDEX note_sub_pubkey ON note_sub(pubkey)")
  db.exec(sql"PRAGMA foreign_keys = ON")

#-------------------------------------------------------------------
# Relay code
#-------------------------------------------------------------------

proc `$`*[T](conn: RelayConnection[T]): string =
  result = "RelayConnectiong("
  result &= &"pubkey={conn.pubkey.abbr} "
  result &= &"sender={conn.sender}"
  if conn.challenge != "":
    result &= " cha=" & base64.encode(conn.challenge)
  result &= ")"

proc `$`*[T](tab: TableRef[PublicKey, RelayConnection[T]]): string =
  result = "TableRef("
  for key in tab.keys():
    let val = tab[key]
    result.add &"{key}: {val}, "
  result &= ")"

proc newRelay*[T](db: DbConn): Relay[T] =
  when TESTMODE:
    resetSkew()
  result.db = db
  result.clients = newTable[PublicKey, RelayConnection[T]]()
  db.updateSchema()

template sendMessage*[T](conn: RelayConnection[T], msg: RelayMessage) =
  when LOG_COMMS:
    info "[" & conn.pubkey.abbr & "] <- " & $msg
  conn.sender.sendMessage(msg)

template sendError*[T](conn: RelayConnection[T], msg: string, cmd: CommandKind, code: ErrorCode) =
  conn.sendMessage(RelayMessage(
    kind: Error,
    err_code: code,
    err_message: msg,
    err_cmd: cmd,
  ))

template sendOkay*[T](conn: RelayConnection[T], cmd: CommandKind) =
  conn.sendMessage(RelayMessage(
    kind: Okay,
    ok_cmd: cmd,
  ))

proc initAuth*[T](relay: Relay[T], client: T): RelayConnection[T] =
  new(result)
  result.sender = client
  result.challenge = randombytes(32)
  result.sendMessage(RelayMessage(
    kind: Who,
    who_challenge: result.challenge,
  ))

proc disconnect*[T](relay: Relay[T], conn: RelayConnection[T]) =
  relay.db.exec(sql"DELETE FROM note_sub WHERE pubkey=?", conn.pubkey.toDB)
  relay.clients.del(conn.pubkey)
  info &"[{conn.pubkey.abbr}] disconnected"

#-------------------------------------------------------------------
# pub/sub notes
#-------------------------------------------------------------------

proc delExpiredNotes(relay: Relay) =
  let offset = when TESTMODE:
      -RELAY_NOTE_DURATION + TIME_SKEW
    else:
      -RELAY_NOTE_DURATION
  let offstring = &"{offset} seconds"
  relay.db.exec(sql"DELETE FROM note WHERE created <= datetime('now', ?)", offstring)

proc addNoteSub(relay: Relay, topic: string, pubkey: PublicKey) =
  ## Record that a pubkey is subscribed to a topic
  try:
    relay.db.exec(sql"INSERT INTO note_sub (topic, pubkey) VALUES (?,?)", topic.DbBlob, pubkey.toDB)
    info &"[{pubkey.abbr}] sub {topic}"
  except:
    raise ValueError.newException("Topic already subscribed")

proc getNoteSub(relay: Relay, topic: string): Option[PublicKey] =
  ## Return a PublicKey who is listening for a note by topic.
  relay.delExpiredNotes()
  let orow = relay.db.getRow(sql"SELECT pubkey FROM note_sub WHERE topic = ?", topic.DbBlob)
  if orow.isSome:
    return some(PublicKey.fromDB(orow.get()[0].s))

proc popNote(relay: Relay, topic: string): Option[string] =
  let db = relay.db
  relay.delExpiredNotes()
  db.exec(sql"BEGIN")
  try:
    let orow = db.getRow(sql"SELECT data FROM note WHERE topic=?", topic.DbBlob)
    if orow.isSome:
      let row = orow.get()
      result = some(row[0].b.string)
      info &"[note] pop {topic}"
      db.exec(sql"DELETE FROM note WHERE topic=?", topic.DbBlob)
    else:
      debug &"[note] dne {topic}"
    db.exec(sql"COMMIT")
  except:
    warn &"[note] error " & getCurrentExceptionMsg()
    db.exec(sql"ROLLBACK")

proc delNoteSub(relay: Relay, topic: string) =
  relay.db.exec(sql"DELETE FROM note_sub WHERE topic = ?", topic.DbBlob)
  info &"[note] del {topic}"


#-------------------------------------------------------------------
# send/receive data
#-------------------------------------------------------------------

proc forgetOldPubkeys(relay: Relay) =
  let offset = when TESTMODE:
      -RELAY_PUBKEY_MEMORY_SECONDS + TIME_SKEW
    else:
      -RELAY_PUBKEY_MEMORY_SECONDS
  let offstring = &"{offset} seconds"
  relay.db.exec(sql"DELETE FROM known_pubkey WHERE last_seen <= datetime('now', ?)", offstring)

proc rememberPubkey(relay: Relay, pubkey: PublicKey) =
  relay.db.exec(sql"""
    INSERT OR REPLACE INTO known_pubkey (pubkey, last_seen)
    VALUES (?, CURRENT_TIMESTAMP)""", pubkey.toDB)

proc isKnown(relay: Relay, pubkey: PublicKey): bool =
  relay.forgetOldPubkeys()
  let orow = relay.db.getRow(sql"SELECT last_seen FROM known_pubkey WHERE pubkey = ?", pubkey.toDB)
  return orow.isSome()

proc delExpiredMessages(relay: Relay) =
  let offset = when TESTMODE:
      -RELAY_MESSAGE_DURATION + TIME_SKEW
    else:
      -RELAY_MESSAGE_DURATION
  let offstring = &"{offset} seconds"
  relay.db.exec(sql"DELETE FROM message WHERE created <= datetime('now', ?)", offstring)

proc nextMessage(relay: Relay, dst: PublicKey): Option[RelayMessage] =
  let orow = relay.db.getRow(sql"""
    SELECT src, data, route_id
    FROM message_dst
    WHERE
      dst = ?
    ORDER BY
      created ASC,
      id ASC
    LIMIT 1""", dst.toDB)
  if orow.isSome:
    let row = orow.get()
    result = some(RelayMessage(
      kind: Data,
      data_src: PublicKey.fromDB(row[0].s),
      data_val: row[1].b.string,
    ))
    relay.db.exec(sql"DELETE FROM message_route WHERE id=?", row[2].i)

#-------------------------------------------------------------------
# relay command handling
#-------------------------------------------------------------------

proc handleCommand*[T](relay: Relay[T], conn: var RelayConnection[T], cmd: RelayCommand) =
  when LOG_COMMS:
    info "[" & conn.pubkey.abbr & "] DO " & $cmd
  case cmd.kind
  of Iam:
    try:
      crypto_sign_verify_detached(cmd.iam_pubkey.string, conn.challenge, cmd.iam_signature)
    except:
      conn.sendError("Invalid signature", cmd.kind, Generic)
      return
    # successful connection
    conn.pubkey = cmd.iam_pubkey
    relay.clients[conn.pubkey] = conn
    conn.challenge = "" # disable authentication
    relay.rememberPubkey(conn.pubkey)
    info &"[{conn.pubkey.abbr}] connected"
    conn.sendOkay cmd.kind

    # send all queued messages
    relay.delExpiredMessages()
    while true:
      let nexto = relay.nextMessage(conn.pubkey)
      if nexto.isSome:
        conn.sendMessage(nexto.get())
      else:
        break
  of PublishNote:
    if cmd.pub_topic.len > RELAY_MAX_TOPIC_SIZE:
      conn.sendError("Topic too long", cmd.kind, TooLarge)
    elif cmd.pub_data.len > RELAY_MAX_NOTE_SIZE:
      conn.sendError("Data too long", cmd.kind, TooLarge)
    else:
      let opubkey = relay.getNoteSub(cmd.pub_topic)
      if opubkey.isSome:
        # someone is waiting
        var other_conn = relay.clients[opubkey.get()]
        conn.sendOkay cmd.kind
        other_conn.sendMessage(RelayMessage(
          kind: Note,
          note_data: cmd.pub_data,
          note_topic: cmd.pub_topic,
        ))
        relay.delNoteSub(cmd.pub_topic)
      else:
        # no one is waiting
        relay.db.exec(sql"INSERT INTO note (topic, data) VALUES (?, ?)",
          cmd.pub_topic.DbBlob,
          cmd.pub_data.DbBlob,
        )
        conn.sendOkay cmd.kind
  of FetchNote:
    if cmd.fetch_topic.len > RELAY_MAX_TOPIC_SIZE:
      conn.sendError("Topic too long", cmd.kind, TooLarge)
    else:
      let odata = relay.popNote(cmd.fetch_topic)
      if odata.isSome():
        # the note is already here
        conn.sendMessage(RelayMessage(
          kind: Note,
          note_data: odata.get(),
          note_topic: cmd.fetch_topic,
        ))
      else:
        # the note isn't here yet
        relay.addNoteSub(cmd.fetch_topic, conn.pubkey)
  of SendData:
    if cmd.data.len > RELAY_MAX_MESSAGE_SIZE:
      conn.sendError("Data too long", cmd.kind, TooLarge)
    else:
      var message_id: Option[int64]
      for dst in cmd.dst:
        if relay.clients.hasKey(dst):
          # dst is online
          var other_conn = relay.clients[dst]
          other_conn.sendMessage(RelayMessage(
            kind: Data,
            data_src: conn.pubkey,
            data_val: cmd.data,
          ))
        else:
          # dst is offline
          if relay.isKnown(dst):
            if message_id.isNone:
              # first one of the recipients that's offline
              let rowid = relay.db.insertID(sql"INSERT INTO message (src, data) VALUES (?, ?)",
                conn.pubkey.toDB, cmd.data.DbBlob)
              message_id = some(rowid)
            relay.db.exec(sql"INSERT INTO message_route (message_id, dst) VALUES (?, ?)",
              message_id.get(), dst.toDB)
          else:
            discard "silently drop the message"
#-------------------------------------------------------------------
# Utilities
#-------------------------------------------------------------------
proc genkeys*(): KeyPair =
  let (pk, sk) = crypto_sign_keypair()
  result = (pk.PublicKey, sk.SecretKey)

proc sign*(key: SecretKey, message: string): string =
  ## Sign a message with the given secret key
  result = crypto_sign_detached(key.string, message)
