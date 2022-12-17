# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/asyncdispatch
import std/asynchttpserver
import std/logging
import std/options
import std/strutils
import std/base64

import ../vend/ws/ws
import protocols/netstring
import ndb/sqlite
import libsodium/sodium

import ./proto
import ./stringproto
import ./dbschema

type
  WSClient = ref object
    ws: WebSocket
    user_id: int64
    relayserver: RelayServer

  RelayServer* = ref object
    relay: Relay[WSClient]
    dbfilename: string
    userdb: Option[DbConn]

# proc sendEvent*(c: WSClient, ev: RelayEvent)

proc newRelayServer*(dbfilename: string): RelayServer =
  new(result)
  result.relay = newRelay[WSClient]()
  result.dbfilename = dbfilename

#-------------------------------------------------------------
# User management
#-------------------------------------------------------------
type
  LowerString* = distinct string

converter toLowercase*(s: string): LowerString = s.toLower().LowerString
converter toString*(s: LowerString): string = s.string

const userdbSchema = [
  ("initial", @[
    """CREATE TABLE IF NOT EXISTS iplog (
      day TEXT NOT NULL,
      ip TEXT NOT NULL,
      bytes_sent INT DEFAULT 0,
      bytes_recv INT DEFAULT 0,
      PRIMARY KEY (day, ip)
    )""",
    """CREATE TABLE IF NOT EXISTS user (
      id INTEGER PRIMARY KEY,
      created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      email TEXT NOT NULL,
      pwhash TEXT NOT NULL,
      emailverified TINYINT DEFAULT 0,
      emailtoken TEXT DEFAULT '',
      blocked TINYINT DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS userlog (
      day TEXT NOT NULL,
      user_id INTEGER,
      bytes_sent INT DEFAULT 0,
      bytes_recv INT DEFAULT 0,
      PRIMARY KEY (day, user_id),
      FOREIGN KEY(user_id) REFERENCES user(id)
    )""",
  ])
]

template boolVal*(d: DbValue): bool =
  d.i == 1

proc db*(rs: RelayServer): DbConn =
  ## Get the user-data database for this server
  if not rs.userdb.isSome:
    var db = open(rs.dbfilename, "", "", "")
    db.exec(sql"PRAGMA foreign_keys = ON")
    db.upgradeSchema(userdbSchema)
    rs.userdb = some(db)
  rs.userdb.get()

proc register_user*(rs: RelayServer, email: LowerString, password: string): int64 =
  ## Register a user with a password
  let pwhash = crypto_pwhash_str(password)
  result = rs.db.insertID(sql"INSERT INTO user (email, pwhash) VALUES (?,?)",
    email, pwhash)

proc password_auth*(rs: RelayServer, email: LowerString, password: string): int64 =
  ## Return the userid if the password is correct, else raise an exception
  let orow = rs.db.getRow(sql"SELECT id, pwhash FROM user WHERE email = ?", email)
  if orow.isNone:
    raise ValueError.newException("No such user")
  else:
    let row = orow.get()
    let user_id = row[0].i
    let pwhash = row[1].s
    if crypto_pwhash_str_verify(pwhash, password):
      return user_id
  raise ValueError.newException("Wrong password")

proc is_email_verified*(rs: RelayServer, user_id: int64): bool =
  ## Return true if the user has verified their email address
  let row = rs.db.getRow(sql"SELECT emailverified FROM user WHERE id=?", user_id)
  if row.isSome:
    return row.get()[0].boolVal

proc generate_email_verification_token*(rs: RelayServer, user_id: int64): string =
  ## Generate a string to be emailed to a user that when returned
  ## to `use_email_verification_token` will mark that user's email
  ## as verified.
  let token = randombytes(3).encodeBase16
  rs.db.exec(sql"UPDATE user SET emailtoken=? WHERE id=?", token, user_id)
  return token

proc use_email_verification_token*(rs: RelayServer, user_id: int64, token: string): bool =
  ## Verify a user's email address via token. Return `true` if they are now
  ## verified and `false` if they are not.
  try:
    let row = rs.db.getRow(sql"SELECT emailtoken FROM user WHERE id=?", user_id).get()
    if row[0].s == token: # a constant-time compare isn't needed because tokens expire on compare
      rs.db.exec(sql"UPDATE user SET emailverified=1 WHERE id=?", user_id)
  except:
    discard
  finally:
    rs.db.exec(sql"UPDATE user SET emailtoken='' WHERE id=?", user_id)
  return rs.is_email_verified(user_id)

proc userid*(rs: RelayServer, email: LowerString): int64 =
  ## Get a user's id from their email
  try:
    rs.db.getRow(sql"SELECT id FROM user WHERE email=?", email).get()[0].i
  except:
    raise ValueError.newException("No such user")

proc block_user*(rs: RelayServer, user_id: int64) =
  ## Block a user's access to the relay
  rs.db.exec(sql"UPDATE user SET blocked=1 WHERE id=?", user_id)

proc block_user*(rs: RelayServer, email: LowerString) =
  ## Block a user's access to the relay
  rs.block_user(rs.userid(email))

proc unblock_user*(rs: RelayServer, user_id: int64) =
  ## Unblock a user's access to the relay
  rs.db.exec(sql"UPDATE user SET blocked=0 WHERE id=?", user_id)

proc unblock_user*(rs: RelayServer, email: LowerString) =
  ## Unblock a user's access to the relay
  rs.unblock_user(rs.userid(email))

proc can_use_relay*(rs: RelayServer, user_id: int64): bool =
  ## Return true if the user is allowed to use the relay
  ## because their email is verified and they are not blocked
  try:
    return rs.db.getRow(sql"SELECT emailverified AND not(blocked) FROM user WHERE id=?", user_id).get()[0].boolVal
  except:
    discard

type
  DataSentRecv* = tuple
    sent: int
    recv: int

proc log_user_data*(rs: RelayServer, user_id: int64, dlen: DataSentRecv) =
  rs.db.exec(sql"""INSERT INTO userlog (day, user_id, bytes_sent, bytes_recv)
    VALUES (date(), ?, ?, ?)
    ON CONFLICT (day, user_id) DO
      UPDATE SET
        bytes_sent = bytes_sent + excluded.bytes_sent,
        bytes_recv = bytes_recv + excluded.bytes_recv
    """, user_id, dlen.sent, dlen.recv)

template log_user_data_sent*(rs: RelayServer, user_id: int64, dlen: int) =
  rs.log_user_data(user_id, (dlen, 0))

template log_user_data_recv*(rs: RelayServer, user_id: int64, dlen: int) =
  rs.log_user_data(user_id, (0, dlen))

proc data_by_user*(rs: RelayServer, user_id: int64, days = 1): DataSentRecv =
  let orow = rs.db.getRow(sql"""
    SELECT
      sum(bytes_sent),
      sum(bytes_recv)
    FROM
      userlog
    WHERE
      user_id = ?
      AND day >= date('now', '-' || ? || ' day')
  """, user_id, days)
  if orow.isSome:
    let row = orow.get()
    return (row[0].i.int, row[1].i.int)

proc top_data_users*(rs: RelayServer, limit = 20, days = 7): seq[tuple[user: string, data: DataSentRecv]] =
  let rows = rs.db.getAllRows(sql"""
    SELECT
      u.email,
      sum(ll.bytes_sent),
      sum(ll.bytes_recv),
      sum(ll.bytes_sent + ll.bytes_recv) as total
    FROM
      userlog as ll
      LEFT JOIN user AS u
        ON ll.user_id = u.id
    WHERE
      ll.day >= date('now', '-' || ? || ' day')
    GROUP BY 1
    ORDER BY total DESC
    LIMIT ?
  """, days, limit)
  for row in rows:
    result.add((row[0].s, (row[1].i.int, row[2].i.int)))

proc log_ip_data*(rs: RelayServer, ip: string, dlen: DataSentRecv) =
  rs.db.exec(sql"""INSERT INTO iplog (day, ip, bytes_sent, bytes_recv)
    VALUES (date(), ?, ?, ?)
    ON CONFLICT (day, ip) DO
      UPDATE SET
        bytes_sent = bytes_sent + excluded.bytes_sent,
        bytes_recv = bytes_recv + excluded.bytes_recv
    """, ip, dlen.sent, dlen.recv)

template log_ip_data_sent*(rs: RelayServer, ip: string, dlen: int) =
  rs.log_ip_data(ip, (dlen, 0))

template log_ip_data_recv*(rs: RelayServer, ip: string, dlen: int) =
  rs.log_ip_data(ip, (0, dlen))

proc data_by_ip*(rs: RelayServer, ip: string, days = 1): DataSentRecv =
  let orow = rs.db.getRow(sql"""
    SELECT
      sum(bytes_sent),
      sum(bytes_recv)
    FROM
      iplog
    WHERE
      ip = ?
      AND day >= date('now', '-' || ? || ' day')
  """, ip, days)
  if orow.isSome:
    let row = orow.get()
    return (row[0].i.int, row[1].i.int)

proc top_data_ips*(rs: RelayServer, limit = 20, days = 7): seq[tuple[ip: string, data: DataSentRecv]] =
  let rows = rs.db.getAllRows(sql"""
    SELECT
      ip,
      sum(bytes_sent),
      sum(bytes_recv),
      sum(bytes_sent + bytes_recv) as total
    FROM
      iplog
    WHERE
      day >= date('now', '-' || ? || ' day')
    GROUP BY 1
    ORDER BY total DESC
    LIMIT ?
  """, days, limit)
  for row in rows:
    result.add((row[0].s, (row[1].i.int, row[2].i.int)))

#-------------------------------------------------------------
# Websockets/network stuff
#-------------------------------------------------------------

proc sendEvent*(c: WSClient, ev: RelayEvent) =
  let msg = nsencode(dumps(ev))
  c.relayserver.log_user_data_recv(c.user_id, msg.len)
  asyncCheck c.ws.send(msg)

proc newWSClient(rs: RelayServer, ws: WebSocket, user_id: int64): WSClient =
  new(result)
  result.ws = ws
  result.relayserver = rs
  result.user_id = user_id

proc authenticate*(rs: RelayServer, req: Request): int64 =
  ## Perform HTTP basic authentication and return the
  ## user id if correct.
  let authorization = req.headers.getOrDefault("authorization")
  let parts = authorization.strip().split(" ")
  doAssert parts.len == 2, "Authorization header should have 2 items"
  doAssert parts[0] == "Basic", "Only basic HTTP auth is supported"
  let credentials = base64.decode(parts[1]).split(":", maxsplit = 1)
  doAssert credentials.len == 2, "Must supply username and password"
  let
    username = credentials[0]
    password = credentials[1]
  return rs.password_auth(username, password)

proc handleRequest*(rs: RelayServer, req: Request) {.async, gcsafe.} =
  ## Handle a relay server websocket request.  See `proc listen` for
  ## an example of how to use this.
  let user_id = block:
    try:
      # Perform HTTP basic authenciation
      rs.authenticate(req)
    except:
      await req.respond(Http403, "Forbidden")
      return
  try:
    # Upgrade protocol to websockets
    var ws = await newWebSocket(req)
    var wsclient = newWSClient(rs, ws, user_id)
    var relayconn = rs.relay.initAuth(wsclient)
    var decoder = newNetstringDecoder()
    while ws.readyState == Open:
      let packet = await ws.receiveStrPacket()
      rs.log_user_data_sent(user_id, packet.len)
      decoder.consume(packet)
      while decoder.hasMessage():
        let cmd = loadsRelayCommand(decoder.nextMessage())
        # echo "server: cmd: ", $cmd
        rs.relay.handleCommand(relayconn, cmd)
    rs.relay.removeConnection(relayconn)
  except WebSocketError:
    error "server: socket closed: " & getCurrentExceptionMsg()
    await req.respond(Http400, "Bad request")
  except:
    error "client failed to connect: " & getCurrentExceptionMsg()
    await req.respond(Http400, "Bad request")

proc listen*(rs: RelayServer, port = 9001.Port, address = "") =
  ## Start the default relay server on the given port.
  var server = newAsyncHttpServer()
  proc cb(req: Request) {.async, gcsafe.} =
    if req.url.path == "/relay":
      await rs.handleRequest(req)
    else:
      await req.respond(Http404, "Not found")
  asyncCheck server.serve(port, cb, address = address)


