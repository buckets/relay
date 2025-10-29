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
    relay*: Relay[T]

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

proc dbValue*(p: PublicKey): DbValue =
  dbValue(p.string.DbBlob)

proc fromDB*(t: typedesc[PublicKey], v: DbBlob): PublicKey =
  v.string.PublicKey

template patch(db: untyped, applied: seq[string], name: string, body: untyped): untyped =
  block:
    if name notin applied:
      info name, " - applying..."
      db.exec(sql"BEGIN")
      try:
        body
        db.exec(sql"INSERT INTO _schema_patches (name) VALUES (?)", name)
        db.exec(sql"COMMIT")
      except CatchableError:
        error name, " - error applying patch: " & getCurrentExceptionMsg()
        db.exec(sql"ROLLBACK")
        raise
    else:
      debug name, " - applied"

proc updateSchema*(db: DbConn) =
  db.exec(sql"PRAGMA foreign_keys = ON")

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
      dst TEXT NOT NULL,
      data BLOB NOT NULL
    )""")
    db.exec(sql"CREATE INDEX message_created ON message(created)")
    db.exec(sql"CREATE INDEX message_dst ON message(dst)")
    
    # chunks
    db.exec(sql"""CREATE TABLE chunk (
      src TEXT NOT NULL,
      key TEXT NOT NULL,
      last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      val BLOB NOT NULL,
      PRIMARY KEY (src, key)
    )""")
    db.exec(sql"CREATE INDEX chunk_last_used ON chunk(last_used)")
    db.exec(sql"""CREATE TABLE chunk_dst (
      src TEXT NOT NULL,
      key TEXT NOT NULL,
      dst TEXT NOT NULL,
      PRIMARY KEY (src, key, dst),
      FOREIGN KEY (src, key) REFERENCES chunk(src, key) ON DELETE CASCADE
    )""")
  
  #----------- in-memory stuff
  db.exec(sql"""CREATE TEMPORARY TABLE note_sub (
    topic TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL
  )""")
  db.exec(sql"CREATE INDEX note_sub_pubkey ON note_sub(pubkey)")
  

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
  result.relay = relay

proc disconnect*[T](relay: Relay[T], conn: RelayConnection[T]) =
  relay.db.exec(sql"DELETE FROM note_sub WHERE pubkey=?", conn.pubkey)
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
    relay.db.exec(sql"INSERT INTO note_sub (topic, pubkey) VALUES (?,?)", topic.DbBlob, pubkey)
    info &"[{pubkey.abbr}] sub {topic}"
  except CatchableError:
    raise ValueError.newException("Topic already subscribed")

proc getNoteSub(relay: Relay, topic: string): Option[PublicKey] =
  ## Return a PublicKey who is listening for a note by topic.
  relay.delExpiredNotes()
  let orow = relay.db.getRow(sql"SELECT pubkey FROM note_sub WHERE topic = ?", topic.DbBlob)
  if orow.isSome:
    return some(PublicKey.fromDB(orow.get()[0].b))

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
  except CatchableError:
    warn &"[note] error " & getCurrentExceptionMsg()
    db.exec(sql"ROLLBACK")

proc delNoteSub(relay: Relay, topic: string) =
  relay.db.exec(sql"DELETE FROM note_sub WHERE topic = ?", topic.DbBlob)
  info &"[note] del {topic}"


#-------------------------------------------------------------------
# send/receive data
#-------------------------------------------------------------------

proc delExpiredMessages(relay: Relay) =
  let offset = when TESTMODE:
      -RELAY_MESSAGE_DURATION + TIME_SKEW
    else:
      -RELAY_MESSAGE_DURATION
  let offstring = &"{offset} seconds"
  relay.db.exec(sql"DELETE FROM message WHERE created <= datetime('now', ?)", offstring)

proc nextMessage(relay: Relay, dst: PublicKey): Option[RelayMessage] =
  let orow = relay.db.getRow(sql"""
    SELECT src, data, id
    FROM message
    WHERE
      dst = ?
    ORDER BY
      created ASC,
      id ASC
    LIMIT 1""", dst)
  if orow.isSome:
    let row = orow.get()
    result = some(RelayMessage(
      kind: Data,
      data_src: PublicKey.fromDB(row[0].b),
      data_val: row[1].b.string,
    ))
    relay.db.exec(sql"DELETE FROM message WHERE id=?", row[2].i)

proc delExpiredChunks(relay: Relay) =
  let offset = when TESTMODE:
      -RELAY_MESSAGE_DURATION + TIME_SKEW
    else:
      -RELAY_MESSAGE_DURATION
  let offstring = &"{offset} seconds"
  relay.db.exec(sql"DELETE FROM chunk WHERE last_used <= datetime('now', ?)", offstring)


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
    except SodiumError:
      conn.sendError("Invalid signature", cmd.kind, Generic)
      return
    except CatchableError:
      conn.sendError("Error validating signature", cmd.kind, Generic)
      return
    # successful connection
    conn.pubkey = cmd.iam_pubkey
    relay.clients[conn.pubkey] = conn
    conn.challenge = "" # disable authentication
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
        try:
          relay.db.exec(sql"INSERT INTO note (topic, data) VALUES (?, ?)",
            cmd.pub_topic.DbBlob,
            cmd.pub_data.DbBlob,
          )
          conn.sendOkay cmd.kind
        except:
          conn.sendError("Duplicate topic", cmd.kind, Generic)
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
    if cmd.send_val.len > RELAY_MAX_MESSAGE_SIZE:
      conn.sendError("Data too long", cmd.kind, TooLarge)
    else:
      if relay.clients.hasKey(cmd.send_dst):
        # dst is online
        var other_conn = relay.clients[cmd.send_dst]
        other_conn.sendMessage(RelayMessage(
          kind: Data,
          data_src: conn.pubkey,
          data_val: cmd.send_val,
        ))
      else:
        # dst is offline
        relay.db.exec(sql"INSERT INTO message (src, dst, data) VALUES (?, ?, ?)",
            conn.pubkey, cmd.send_dst, cmd.send_val.DbBlob)
  of StoreChunk:
    if cmd.chunk_key.len > RELAY_MAX_CHUNK_KEY_SIZE:
      conn.sendError("Key too long", cmd.kind, TooLarge)
    elif cmd.chunk_val.len > RELAY_MAX_CHUNK_SIZE:
      conn.sendError("Value too long", cmd.kind, TooLarge)
    elif cmd.chunk_dst.len > RELAY_MAX_CHUNK_DSTS:
      conn.sendError("Too many recipients", cmd.kind, TooLarge)
    else:
      relay.db.exec(sql"BEGIN")
      try:
        relay.db.exec(sql"DELETE FROM chunk_dst WHERE src=? AND key=?", conn.pubkey, cmd.chunk_key.DbBlob)
        let offset = when TESTMODE:
            $TIME_SKEW & " seconds"
          else:
            "0 seconds"
        relay.db.exec(sql"""
          INSERT OR REPLACE INTO chunk (last_used, src, key, val)
          VALUES (datetime('now', ?), ?, ?, ?)
          """, offset, conn.pubkey, cmd.chunk_key.DbBlob, cmd.chunk_val.DbBlob)
        var dsts: seq[PublicKey]
        dsts.add(cmd.chunk_dst)
        if conn.pubkey notin dsts:
          dsts.add(conn.pubkey)
        for dst in dsts:
          relay.db.exec(sql"INSERT INTO chunk_dst (src, key, dst) VALUES (?, ?, ?)",
            conn.pubkey, cmd.chunk_key.DbBlob, dst)
        relay.db.exec(sql"COMMIT")
      except CatchableError:
        relay.db.exec(sql"ROLLBACK")
  of GetChunks:
    for key in cmd.chunk_keys:
      if key.len > RELAY_MAX_CHUNK_KEY_SIZE:
        conn.sendError("Key too long", cmd.kind, TooLarge)
        return
    relay.delExpiredChunks()
    for key in cmd.chunk_keys:
      let orow = relay.db.getRow(sql"""
        SELECT
          c.val
        FROM
          chunk_dst AS d
          JOIN chunk AS c
            ON d.src = c.src
              AND d.key = c.key
        WHERE
          d.src = ?
          AND d.key = ?
          AND d.dst = ?
        """, cmd.chunk_src, key.DbBlob, conn.pubkey)
      if orow.isSome:
        let row = orow.get()
        conn.sendMessage(RelayMessage(
          kind: Chunk,
          chunk_src: cmd.chunk_src,
          chunk_key: key,
          chunk_val: some(row[0].b.string),
        ))
      else:
        conn.sendMessage(RelayMessage(
          kind: Chunk,
          chunk_src: cmd.chunk_src,
          chunk_key: key,
          chunk_val: none[string](),
        ))
#-------------------------------------------------------------------
# Utilities
#-------------------------------------------------------------------
proc genkeys*(): KeyPair =
  let (pk, sk) = crypto_sign_keypair()
  result = (pk.PublicKey, sk.SecretKey)

proc sign*(key: SecretKey, message: string): string =
  ## Sign a message with the given secret key
  result = crypto_sign_detached(key.string, message)
