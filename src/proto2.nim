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
import libsodium/sodium_sizes

import ./objs; export objs

const LOG_COMMS* = not defined(release)
const TESTMODE = defined(testmode) and not defined(release)

type
  KeyPair* = tuple
    pk: PublicKey
    sk: SecretKey

  Relay*[T] = object
    db*: DbConn
    clients: TableRef[PublicKey, RelayConnection[T]]
    max_chunk_space*: int
    max_transfer_rate*: int
  
  RelayConnection*[T] = ref object
    sender*: T
    pubkey*: Option[PublicKey] ## The authenticated pubkey
    challenge: Option[Challenge]
    relay*: Relay[T]
    ip*: string

when TESTMODE:
  var TIME_SKEW = 0
  proc skewTime*(seconds: int) =
    TIME_SKEW += seconds
  proc skewTime*(dur: Duration) =
    TIME_SKEW += dur.inSeconds()
  proc resetSkew*() =
    TIME_SKEW = 0

#-------------------------------------------------------------------
# Utilities
#-------------------------------------------------------------------
proc genkeys*(): KeyPair =
  let (pk, sk) = crypto_sign_keypair()
  result = (pk.PublicKey, sk.SecretKey)

proc sign*(key: SecretKey, message: string): string =
  ## Sign a message with the given secret key
  result = crypto_sign_detached(key.string, message)

proc is_valid_signature*(key: PublicKey, plaintext: string, signature: string): bool =
  try:
    crypto_sign_verify_detached(key.string, plaintext, signature)
    return true
  except SodiumError:
    return false
  except CatchableError:
    return false

const
  CHALLENGE_BITS = when TESTMODE: 1 else: 5

proc generateChallenge*(bits = CHALLENGE_BITS, opslimit = crypto_pwhash_opslimit_interactive().int, memlimit = crypto_pwhash_memlimit_interactive().int): Challenge =
  return (
    bits: bits,
    rand: randombytes(32) & $epochTime(),
    opslimit: opslimit,
    memlimit: memlimit,
  )

proc sigContents*(ch: Challenge, nonce: int, output: string): string =
  ch.serialize & nsencode($nonce) & output

proc firstBits(s: string, n: int): string =
  ## Returns the first `n` bits of the string `s` as a binary string.
  if s.len * 8 < n:
    raise ValueError.newException("String not long enough")
  var bitsLeft = n
  for i in 0..<min(s.len, (n + 7) div 8):
    var byte = ord(s[i]).uint8
    for bit in countdown(7, 0):
      if bitsLeft > 0:
        result.add(if (byte and (1'u8 shl bit)) != 0: '1' else: '0')
        dec bitsLeft
      else:
        return result
  if bitsLeft > 0:
    # this should never happen, but just in case
    raise ValueError.newException("String not long enough")
  return result

proc answer*(ch: Challenge, sk: SecretKey): ChallengeAnswer =
  ## Answer a hashcash challenge and sign the result
  var nonce = 0
  let serialized = ch.serialize()
  var start = getTime()
  var expected_prefix = '0'.repeat(ch.bits)
  while true:
    let inp = serialized & ":" & $nonce
    let output = crypto_pwhash_str(inp,
      opslimit = ch.opslimit.csize_t,
      memlimit = ch.memlimit.csize_t)
    let hashpart = base64.decode(output.split('$')[^1])
    let bits = hashpart.firstBits(ch.bits)
    if bits == expected_prefix:
      var diff = getTime() - start
      return (
        nonce: nonce,
        output: output,
        signature: sk.sign(sigContents(ch, nonce, output)),
      )
    nonce.inc()

proc is_valid_answer*(pk: PublicKey, ch: Challenge, answer: ChallengeAnswer): bool =
  ## Verify the signed challenge answer
  if not pk.is_valid_signature(sigContents(ch, answer.nonce, answer.output), answer.signature):
    return false
  let inp = ch.serialize() & ":" & $answer.nonce
  if crypto_pwhash_str_verify(answer.output, inp) == false:
    return false
  return true


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
      src TEXT NOT NULL,
      data BLOB DEFAULT ''
    )""")
    db.exec(sql"CREATE INDEX note_created ON note(created)")
    db.exec(sql"CREATE INDEX note_src ON note(src)")
    
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

    # stats
    db.exec(sql"""CREATE TABLE stats_transfer (
      period TEXT NOT NULL DEFAULT(strftime('%Y-%W')),
      ip TEXT NOT NULL,
      pubkey TEXT NOT NULL,
      data_in INTEGER DEFAULT 0,
      data_out INTEGER DEFAULT 0,
      PRIMARY KEY (period, ip, pubkey)
    )""")
  db.patch(applied, "connects"):
    db.exec(sql"""CREATE TABLE stats_event (
      period TEXT NOT NULL DEFAULT(strftime('%Y-%W')),
      ip TEXT NOT NULL,
      pubkey TEXT NOT NULL,
      connect INTEGER DEFAULT 0,
      publish INTEGER DEFAULT 0,
      send INTEGER DEFAULT 0,
      store INTEGER DEFAULT 0,
      PRIMARY KEY (period, ip, pubkey)
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
  if conn.challenge.isSome:
    result &= " cha=" & base64.encode(conn.challenge.get())
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
  result.challenge = some(generateChallenge())
  result.sendMessage(RelayMessage(
    kind: Who,
    who_challenge: result.challenge.get(),
  ))
  result.relay = relay

proc disconnect*[T](relay: Relay[T], conn: RelayConnection[T]) =
  if conn.pubkey.isSome:
    let pubkey = conn.pubkey.get()
    relay.db.exec(sql"DELETE FROM note_sub WHERE pubkey=?", pubkey)
    relay.clients.del(pubkey)
  info &"[{conn.pubkey.abbr}] disconnected"

#-------------------------------------------------------------------
# stats
#-------------------------------------------------------------------
type
  TransferTotal* = tuple
    data_in: int
    data_out: int
    ip: string
    pubkey: PublicKey
    period: string
  
  PeriodRange* = tuple
    a: string
    b: string

proc record_transfer_stat*(db: DbConn, ip: string, pubkey = "".PublicKey, data_in = 0, data_out = 0) =
  db.exec(sql"""
  INSERT INTO stats_transfer (ip, pubkey, data_in, data_out)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(period, ip, pubkey) DO UPDATE SET
    data_in = data_in + excluded.data_in,
    data_out = data_out + excluded.data_out;
  """, ip, pubkey, data_in, data_out)

when TESTMODE:
  proc record_transfer_stat_period*(db: DbConn, ip: string, pubkey = "".PublicKey, period = "", data_in = 0, data_out = 0) =
    db.exec(sql"""
    INSERT INTO stats_transfer (ip, pubkey, period, data_in, data_out)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(period, ip, pubkey) DO UPDATE SET
      data_in = data_in + excluded.data_in,
      data_out = data_out + excluded.data_out;
    """, ip, pubkey, period, data_in, data_out)

proc record_event_stat*(db: DbConn, ip: string, pubkey: PublicKey, connect = 0, publish = 0, send = 0, store = 0) =
  db.exec(sql"""
  INSERT INTO stats_event (ip, pubkey, connect, publish, send, store)
  VALUES (?, ?, ?, ?, ?, ?)
  ON CONFLICT(period, ip, pubkey) DO UPDATE SET
    connect = connect + excluded.connect,
    publish = publish + excluded.publish,
    send = send + excluded.send,
    store = store + excluded.store
  """, ip, pubkey, connect, publish, send, store)

proc chunk_space_used*(db: DbConn, pubkey: PublicKey): int =
  ## Return the amount of space being used by the given public key
  db.getRow(sql"""
    SELECT coalesce(sum(length(val)), 0) FROM chunk WHERE src = ?
  """, pubkey).get()[0].i.int

proc current_data_in*(db: DbConn, pubkey: PublicKey): int =
  ## Return the amount of data that has been transferred in by the given
  ## public key for the current time period
  db.getRow(sql"""
    SELECT coalesce(sum(data_in), 0) FROM stats_transfer
    WHERE
      pubkey = ?
      AND period = strftime('%Y-%W')
  """, pubkey).get()[0].i.int

proc stats_transfer_total*(db: DbConn, ip = "", pubkey = "".PublicKey, period = ""): TransferTotal =
  var query = "SELECT sum(data_in), sum(data_out) FROM stats_transfer"
  var whereparts: seq[string]
  var params: seq[DbValue]
  var groupby: seq[string]
  if period != "":
    whereparts.add "period=?"
    params.add(period.dbValue())
  if ip != "":
    whereparts.add "ip=?"
    params.add(ip.dbValue())
  if pubkey.string != "":
    whereparts.add "pubkey=?"
    params.add(pubkey.dbValue())
  if whereparts.len > 0:
    query &= " WHERE " & whereparts.join(" AND ")
  let orow = db.getRow(sql(query), params)
  if orow.isSome():
    let row = orow.get()
    return (row[0].i.int, row[1].i.int, ip, pubkey, period)

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

proc noteCount(relay: Relay, pubkey: PublicKey): int =
  ## Return the number of notes currently published by this ip
  relay.db.getRow(sql"SELECT count(*) FROM note WHERE src = ?", pubkey).get()[0].i.int

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
  if conn.pubkey.isNone and cmd.kind != Iam:
    conn.sendError("Not allowed", cmd.kind, NotAllowed)
    return

  case cmd.kind
  of Iam:
    if conn.challenge.isNone:
      conn.sendError("Already authenticated", cmd.kind, Generic)
      return
    let challenge = conn.challenge.get()
    conn.challenge = none[Challenge]() # disable future authentication attempts
    
    try:
      if not is_valid_answer(cmd.iam_pubkey, challenge, cmd.iam_answer):
        conn.sendError("Invalid answer", cmd.kind, Generic)
        return
    except CatchableError:
      conn.sendError("Invalid answer", cmd.kind, Generic)
      return

    # successful connection
    let pubkey = cmd.iam_pubkey
    conn.pubkey = some(pubkey)
    relay.clients[pubkey] = conn
    info &"[{conn.pubkey.abbr}] connected"
    conn.sendOkay cmd.kind
    relay.db.record_event_stat(
      ip = conn.ip,
      pubkey = pubkey,
      connect = 1,
    )

    # send all queued messages
    relay.delExpiredMessages()
    while true:
      let nexto = relay.nextMessage(pubkey)
      if nexto.isSome:
        let msg = nexto.get()
        conn.sendMessage(msg)
        if msg.kind == Data:
          relay.db.record_transfer_stat(
            ip = conn.ip,
            pubkey = pubkey,
            data_out = msg.data_val.len,
          )
      else:
        break
  of PublishNote:
    if cmd.pub_topic.len > RELAY_MAX_TOPIC_SIZE:
      conn.sendError("Topic too long", cmd.kind, TooLarge)
    elif cmd.pub_data.len > RELAY_MAX_NOTE_SIZE:
      conn.sendError("Data too long", cmd.kind, TooLarge)
    else:
      let pubkey = conn.pubkey.get()
      if relay.noteCount(pubkey) >= RELAY_MAX_NOTES:
        conn.sendError("Too many notes", cmd.kind, StorageLimitExceeded)
      else:
        relay.db.record_transfer_stat(
          ip = conn.ip,
          pubkey = pubkey,
          data_in = cmd.pub_data.len,
        )
        relay.db.record_event_stat(
          ip = conn.ip,
          pubkey = pubkey,
          publish = 1,
        )
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
          relay.db.record_transfer_stat(
            ip = other_conn.ip,
            pubkey = other_conn.pubkey.get(),
            data_out = cmd.pub_data.len,
          )
        else:
          # no one is waiting
          try:
            relay.db.exec(sql"INSERT INTO note (topic, data, src) VALUES (?, ?, ?)",
              cmd.pub_topic.DbBlob,
              cmd.pub_data.DbBlob,
              pubkey,
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
        let data = odata.get()
        conn.sendMessage(RelayMessage(
          kind: Note,
          note_data: data,
          note_topic: cmd.fetch_topic,
        ))
        relay.db.record_transfer_stat(
          ip = conn.ip,
          pubkey = conn.pubkey.get(),
          data_out = data.len,
        )
      else:
        # the note isn't here yet
        relay.addNoteSub(cmd.fetch_topic, conn.pubkey.get())
  of SendData:
    if cmd.send_val.len > RELAY_MAX_MESSAGE_SIZE:
      conn.sendError("Data too long", cmd.kind, TooLarge)
    else:
      let pubkey = conn.pubkey.get()
      if relay.max_transfer_rate != 0 and relay.db.current_data_in(pubkey) > relay.max_transfer_rate:
        conn.sendError("Rate limit exceeded", cmd.kind, TransferLimitExceeeded)
      else:
        relay.db.record_transfer_stat(
          ip = conn.ip,
          pubkey = pubkey,
          data_in = cmd.send_val.len,
        )
        relay.db.record_event_stat(
          ip = conn.ip,
          pubkey = pubkey,
          send = 1,
        )
        if relay.clients.hasKey(cmd.send_dst):
          # dst is online
          var other_conn = relay.clients[cmd.send_dst]
          other_conn.sendMessage(RelayMessage(
            kind: Data,
            data_src: pubkey,
            data_val: cmd.send_val,
          ))
          relay.db.record_transfer_stat(
            ip = other_conn.ip,
            pubkey = other_conn.pubkey.get(),
            data_in = cmd.send_val.len,
          )
        else:
          # dst is offline
          relay.db.exec(sql"INSERT INTO message (src, dst, data) VALUES (?, ?, ?)",
              pubkey, cmd.send_dst, cmd.send_val.DbBlob)
  of StoreChunk:
    if cmd.chunk_key.len > RELAY_MAX_CHUNK_KEY_SIZE:
      conn.sendError("Key too long", cmd.kind, TooLarge)
    elif cmd.chunk_val.len > RELAY_MAX_CHUNK_SIZE:
      conn.sendError("Value too long", cmd.kind, TooLarge)
    elif cmd.chunk_dst.len > RELAY_MAX_CHUNK_DSTS:
      conn.sendError("Too many recipients", cmd.kind, TooLarge)
    else:
      let pubkey = conn.pubkey.get()
      if relay.max_chunk_space > 0 and relay.db.chunk_space_used(pubkey) > relay.max_chunk_space:
        conn.sendError("Too much chunk data", cmd.kind, StorageLimitExceeded)
      else:
        relay.db.record_event_stat(
          ip = conn.ip,
          pubkey = pubkey,
          store = 1,
        )
        relay.db.exec(sql"BEGIN")
        try:
          relay.db.exec(sql"DELETE FROM chunk_dst WHERE src=? AND key=?", pubkey, cmd.chunk_key.DbBlob)
          let offset = when TESTMODE:
              $TIME_SKEW & " seconds"
            else:
              "0 seconds"
          relay.db.exec(sql"""
            INSERT OR REPLACE INTO chunk (last_used, src, key, val)
            VALUES (datetime('now', ?), ?, ?, ?)
            """, offset, pubkey, cmd.chunk_key.DbBlob, cmd.chunk_val.DbBlob)
          var dsts: seq[PublicKey]
          dsts.add(cmd.chunk_dst)
          if pubkey notin dsts:
            dsts.add(pubkey)
          for dst in dsts:
            relay.db.exec(sql"INSERT INTO chunk_dst (src, key, dst) VALUES (?, ?, ?)",
              pubkey, cmd.chunk_key.DbBlob, dst)
          relay.db.exec(sql"COMMIT")
        except CatchableError:
          relay.db.exec(sql"ROLLBACK")
  of GetChunks:
    for key in cmd.chunk_keys:
      if key.len > RELAY_MAX_CHUNK_KEY_SIZE:
        conn.sendError("Key too long", cmd.kind, TooLarge)
        return
    relay.delExpiredChunks()
    let pubkey = conn.pubkey.get()
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
        """, cmd.chunk_src, key.DbBlob, pubkey)
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
  of HasChunks:
    for key in cmd.has_keys:
      if key.len > RELAY_MAX_CHUNK_KEY_SIZE:
        conn.sendError("Key too long", cmd.kind, TooLarge)
        return
    relay.delExpiredChunks()
    let pubkey = conn.pubkey.get()
    var present: seq[string]
    var absent: seq[string]
    for key in cmd.has_keys:
      let orow = relay.db.getRow(sql"""
        SELECT
          1
        FROM
          chunk_dst AS d
          JOIN chunk AS c
            ON d.src = c.src
              AND d.key = c.key
        WHERE
          d.src = ?
          AND d.key = ?
          AND d.dst = ?
        """, cmd.has_src, key.DbBlob, pubkey)
      if orow.isSome:
        present.add(key)
        if cmd.has_src == pubkey:
          # reset the expiration of the chunk, since the owner
          # is touching it
          let offset = when TESTMODE:
              $TIME_SKEW & " seconds"
            else:
              "0 seconds"
          relay.db.exec(sql"""
            UPDATE chunk SET last_used = datetime('now', ?) WHERE src = ? AND key = ?
            """, offset, cmd.has_src, key.DbBlob)
      else:
        absent.add(key)
    conn.sendMessage(RelayMessage(
      kind: ChunkStatus,
      status_src: cmd.has_src,
      present: present,
      absent: absent,
    ))
