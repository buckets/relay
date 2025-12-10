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

const LOG_COMMS* = not defined(release) or defined(relaynologcomms)
const TESTMODE = defined(testmode) and not defined(release)

type
  KeyPair* = tuple
    pk: SignPublicKey
    sk: SignSecretKey

  Relay*[T] = object
    db*: DbConn
    clients: TableRef[SignPublicKey, RelayConnection[T]]
    max_chunk_space*: int
    max_transfer_rate*: int
  
  RelayConnection*[T] = ref object
    sender*: T
    pubkey*: Option[SignPublicKey] ## The authenticated pubkey
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
  result = (pk.SignPublicKey, sk.SignSecretKey)

proc sign*(key: SignSecretKey, message: string): string =
  ## Sign a message with the given secret key
  result = crypto_sign_detached(key.string, message)

proc is_valid_signature*(key: SignPublicKey, plaintext: string, signature: string): bool =
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

proc answer*(ch: Challenge, sk: SignSecretKey): ChallengeAnswer =
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

proc is_valid_answer*(pk: SignPublicKey, ch: Challenge, answer: ChallengeAnswer): bool =
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

proc dbValue*(p: SignPublicKey): DbValue =
  dbValue(p.string.DbBlob)

proc fromDB*(t: typedesc[SignPublicKey], v: DbBlob): SignPublicKey =
  v.string.SignPublicKey

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
      key BLOB NOT NULL,
      src TEXT NOT NULL,
      dst TEXT NOT NULL,
      data BLOB NOT NULL
    )""")
    db.exec(sql"CREATE INDEX message_created ON message(created)")
    db.exec(sql"""CREATE UNIQUE INDEX message_dst_key
      ON message(dst, key)
      WHERE key IS NOT x''
    """)

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
      PRIMARY KEY (period, ip, pubkey)
    )""")


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

proc `$`*[T](tab: TableRef[SignPublicKey, RelayConnection[T]]): string =
  result = "TableRef("
  for key in tab.keys():
    let val = tab[key]
    result.add &"{key}: {val}, "
  result &= ")"

proc newRelay*[T](db: DbConn): Relay[T] =
  when TESTMODE:
    resetSkew()
  result.db = db
  result.clients = newTable[SignPublicKey, RelayConnection[T]]()
  db.updateSchema()

template sendError*[T](conn: RelayConnection[T], cmd: RelayCommand, msg: string, code: ErrorCode) =
  conn.sendMessage(RelayMessage(
    kind: Error,
    resp_id: cmd.resp_id,
    err_code: code,
    err_message: msg,
    err_cmd: cmd.kind,
  ))

template sendOkay*[T](conn: RelayConnection[T], cmd: RelayCommand) =
  conn.sendMessage(RelayMessage(
    kind: Okay,
    resp_id: cmd.resp_id,
    ok_cmd: cmd.kind,
  ))

proc is_valid*(x: SignPublicKey): bool =
  ## Return true if it looks like a valid public key
  if x.string.len == 32:
    return true
  return false

proc any_invalid(x: seq[SignPublicKey]): bool =
  ## Return true if any of the public keys are invalid
  for pk in x:
    if not pk.is_valid():
      return true
  return false

proc initAuth*[T](relay: Relay[T], client: T): RelayConnection[T] =
  new(result)
  result.sender = client
  result.challenge = some(generateChallenge())
  result.sendMessage(RelayMessage(
    kind: Who,
    resp_id: 0,  # Who messages are not triggered by a command
    who_challenge: result.challenge.get(),
  ))
  result.relay = relay

proc disconnect*[T](relay: Relay[T], conn: RelayConnection[T]) =
  if conn.pubkey.isSome:
    let pubkey = conn.pubkey.get()
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
    pubkey: SignPublicKey
    period: string
  
  PeriodRange* = tuple
    a: string
    b: string

proc record_transfer_stat*(db: DbConn, ip: string, pubkey = "".SignPublicKey, data_in = 0, data_out = 0) =
  db.exec(sql"""
  INSERT INTO stats_transfer (ip, pubkey, data_in, data_out)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(period, ip, pubkey) DO UPDATE SET
    data_in = data_in + excluded.data_in,
    data_out = data_out + excluded.data_out;
  """, ip, pubkey, data_in, data_out)

when TESTMODE:
  proc record_transfer_stat_period*(db: DbConn, ip: string, pubkey = "".SignPublicKey, period = "", data_in = 0, data_out = 0) =
    db.exec(sql"""
    INSERT INTO stats_transfer (ip, pubkey, period, data_in, data_out)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(period, ip, pubkey) DO UPDATE SET
      data_in = data_in + excluded.data_in,
      data_out = data_out + excluded.data_out;
    """, ip, pubkey, period, data_in, data_out)

proc record_event_stat*(db: DbConn, ip: string, pubkey: SignPublicKey, connect = 0, publish = 0, send = 0) =
  db.exec(sql"""
  INSERT INTO stats_event (ip, pubkey, connect, publish, send)
  VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(period, ip, pubkey) DO UPDATE SET
    connect = connect + excluded.connect,
    publish = publish + excluded.publish,
    send = send + excluded.send
  """, ip, pubkey, connect, publish, send)

proc current_data_in*(db: DbConn, pubkey: SignPublicKey): int =
  ## Return the amount of data that has been transferred in by the given
  ## public key for the current time period
  db.getRow(sql"""
    SELECT coalesce(sum(data_in), 0) FROM stats_transfer
    WHERE
      pubkey = ?
      AND period = strftime('%Y-%W')
  """, pubkey).get()[0].i.int

proc stats_transfer_total*(db: DbConn, ip = "", pubkey = "".SignPublicKey, period = ""): TransferTotal =
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

proc noteCount(relay: Relay, pubkey: SignPublicKey): int =
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

proc nextMessage(relay: Relay, dst: SignPublicKey): Option[RelayMessage] =
  let orow = relay.db.getRow(sql"""
    SELECT key, src, data, id
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
      resp_id: 0,  # Data messages are not triggered by recipient's command
      data_key: row[0].b.string,
      data_src: SignPublicKey.fromDB(row[1].b),
      data_val: row[2].b.string,
    ))
    relay.db.exec(sql"DELETE FROM message WHERE id=?", row[3].i)

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
    conn.sendError(cmd, "Not allowed", NotAllowed)
    return

  case cmd.kind
  of Iam:
    if conn.challenge.isNone:
      conn.sendError(cmd, "Already authenticated", Generic)
      return
    let challenge = conn.challenge.get()
    conn.challenge = none[Challenge]() # disable future authentication attempts

    try:
      if not is_valid_answer(cmd.iam_pubkey, challenge, cmd.iam_answer):
        conn.sendError(cmd, "Invalid answer", Generic)
        return
    except CatchableError:
      conn.sendError(cmd, "Invalid answer", Generic)
      return

    # successful connection
    let pubkey = cmd.iam_pubkey
    conn.pubkey = some(pubkey)
    relay.clients[pubkey] = conn
    info &"[{conn.pubkey.abbr}] connected"
    conn.sendOkay(cmd)
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
            data_out = msg.data_val.len + msg.data_key.len,
          )
      else:
        break
  of PublishNote:
    if cmd.pub_topic.len > RELAY_MAX_TOPIC_SIZE:
      conn.sendError(cmd, "Topic too long", TooLarge)
    elif cmd.pub_data.len > RELAY_MAX_NOTE_SIZE:
      conn.sendError(cmd, "Data too long", TooLarge)
    else:
      let pubkey = conn.pubkey.get()
      if relay.noteCount(pubkey) >= RELAY_MAX_NOTES:
        conn.sendError(cmd, "Too many notes", StorageLimitExceeded)
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
        try:
          relay.db.exec(sql"INSERT INTO note (topic, data, src) VALUES (?, ?, ?)",
            cmd.pub_topic.DbBlob,
            cmd.pub_data.DbBlob,
            pubkey,
          )
          conn.sendOkay(cmd)
        except:
          conn.sendError(cmd, "Duplicate topic", Generic)
  of FetchNote:
    if cmd.fetch_topic.len > RELAY_MAX_TOPIC_SIZE:
      conn.sendError(cmd, "Topic too long", TooLarge)
    else:
      let odata = relay.popNote(cmd.fetch_topic)
      if odata.isSome():
        # the note is already here
        let data = odata.get()
        conn.sendMessage(RelayMessage(
          kind: Note,
          resp_id: cmd.resp_id,  # Response to FetchNote command
          note_data: data,
          note_topic: cmd.fetch_topic,
        ))
        relay.db.record_transfer_stat(
          ip = conn.ip,
          pubkey = conn.pubkey.get(),
          data_out = data.len,
        )
      else:
        # the note doesn't exist
        conn.sendError(cmd, "Topic not found", NotFound)
  of SendData:
    if cmd.send_val.len > RELAY_MAX_MESSAGE_SIZE:
      conn.sendError(cmd, "Data too long", TooLarge)
    elif cmd.send_key.len > RELAY_MAX_KEY_SIZE:
      conn.sendError(cmd, "Key too long", TooLarge)
    elif cmd.send_dst.any_invalid():
      conn.sendError(cmd, "Invalid pubkey", InvalidParams)
    else:
      let pubkey = conn.pubkey.get()
      if relay.max_transfer_rate != 0 and relay.db.current_data_in(pubkey) > relay.max_transfer_rate:
        conn.sendError(cmd, "Rate limit exceeded", TransferLimitExceeeded)
      else:
        relay.db.record_transfer_stat(
          ip = conn.ip,
          pubkey = pubkey,
          data_in = cmd.send_val.len + cmd.send_key.len,
        )
        relay.db.record_event_stat(
          ip = conn.ip,
          pubkey = pubkey,
          send = 1,
        )
        for dst_pubkey in cmd.send_dst:
          if relay.clients.hasKey(dst_pubkey):
            # dst is online
            var other_conn = relay.clients[dst_pubkey]
            other_conn.sendMessage(RelayMessage(
              kind: Data,
              resp_id: 0,  # Not triggered by other_conn's command
              data_key: cmd.send_key,
              data_src: pubkey,
              data_val: cmd.send_val,
            ))
            relay.db.record_transfer_stat(
              ip = other_conn.ip,
              pubkey = other_conn.pubkey.get(),
              data_out = cmd.send_val.len + cmd.send_key.len,
            )
          else:
            # dst is offline
            relay.db.exec(sql"""
              INSERT OR REPLACE INTO message
              (key, src, dst, data)
              VALUES (?, ?, ?, ?)""",
              cmd.send_key.DbBlob, pubkey, dst_pubkey, cmd.send_val.DbBlob)
