import std/asyncdispatch
import std/base64
import std/deques
import std/httpcore
import std/logging
import std/os
import std/strformat
import std/strutils

import jester
import nimja
import ws
import ws/jester_extra
import lowdb/sqlite
import libsodium/sodium

import ./proto2
import ./objs

type
  NetstringSocket = ref object
    buf: string
    socket: WebSocket
    ip: string
    pubkey: Option[SignPublicKey]
  
  QueuedMessage = tuple
    socket: NetstringSocket
    msg: RelayMessage

const
  VERSION = slurp"../CHANGELOG.md".split(" ")[1]
  logo_png = slurp"./static/logo.png"
  favicon_png = slurp"./static/favicon.png"

let ADMIN_USERNAME = getEnv("ADMIN_USERNAME", "admin")
let ADMIN_PWHASH = when defined(release):
    getEnv("ADMIN_PWHASH", "")
  else:
    # the password is 'admin'
    getEnv("ADMIN_PWHASH", "$argon2id$v=19$m=262144,t=3,p=1$AxXWW9mRuyJjWWbxa4WYoQ$xHAyhzWgKGFH+amM4D1GMuNsPSjGNNp40MueB9dJkgA")

var relay: Relay[NetstringSocket] 
var message_queue = initDeque[QueuedMessage]()

proc trueClientIP(request: Request): string =
  ## Return the true, originating client IP of a request
  # CF-Connecting-IP (cloudflare)
  result = request.headers.getOrDefault("cf-connecting-ip")
  if result != "":
    return result
  # True-Client-IP (cloudflare)
  result = request.headers.getOrDefault("true-client-ip")
  if result != "":
    return result
  # X-Real-IP (nginx)
  result = request.headers.getOrDefault("x-real-ip")
  if result != "":
    return result
  result = request.ip

proc isAdmin(request: Request): bool =
  if not request.headers.hasKey("Authorization"):
    return false
  let authHeader = request.headers["Authorization"]
  let encodedCreds = authHeader[("Basic ".len)..^1]

  try:
    let decodedCreds = base64.decode(encodedCreds)
    let parts = decodedCreds.split(":", 1)
    if parts.len == 2:
      let username = parts[0]
      let password = parts[1]
      return sodium.memcmp(username, ADMIN_USERNAME) and crypto_pwhash_str_verify(ADMIN_PWHASH, password)
  except CatchableError:
    return false

  return false

proc wcommas(x: int): string = insertSep($x, sep = ',')

proc newNetstringSocket(sock: WebSocket, ip: string): NetstringSocket =
  new(result)
  result.socket = sock
  result.ip = ip

proc receiveString(ns: NetstringSocket): Future[string] {.async.} =
  while true:
    try:
      return ns.buf.nschop()
    except IncompleteNetstring:
      discard
    let packet = await ns.socket.receiveStrPacket()
    ns.buf &= packet  

proc sendString(ns: NetstringSocket, msg: string): Future[void] {.async.} =
  let tosend = nsencode(msg)
  await ns.socket.send(tosend)

proc receiveCommand(relay: Relay, ns: NetstringSocket): Future[RelayCommand] {.async.} =
  let s = await ns.receiveString()
  return RelayCommand.deserialize(s)

proc sendMessage(ns: NetstringSocket, msg: RelayMessage) {.async.} =
  await ns.sendString(msg.serialize())

proc sendMessage(conn: RelayConnection[NetstringSocket], msg: RelayMessage) =
  message_queue.addLast((conn.sender, msg))

proc sendQueuedMessages() {.async.} =
  while message_queue.len > 0:
    let (sock, msg) = message_queue.popFirst()
    await sock.sendMessage(msg)

proc handleWebsocket(req: Request) {.async, gcsafe.} =
  var ws = await newWebSocket(req)
  var ns = newNetstringSocket(ws, req.trueClientIP())
  var conn = relay.initAuth(ns)
  conn.ip = req.trueClientIP()
  await sendQueuedMessages()
  while ns.socket.readyState == Open:
    let cmd = try:
      await relay.receiveCommand(ns)
    except WebSocketClosedError:
      break
    except WebSocketProtocolMismatchError:
      warn "Socket tried to use an unknown protocol: ", getCurrentExceptionMsg()
      break
    except WebSocketError:
      warn "Unexpected socket error: ", getCurrentExceptionMsg()
      break
    except CatchableError:
      warn "CatchableError: ", getCurrentExceptionMsg()
      break
    relay.handleCommand(conn, cmd)
    if cmd.kind == Iam:
      ns.pubkey = conn.pubkey
    await sendQueuedMessages()
  relay.disconnect(conn)

type
  StorageStat = tuple
    pubkey: SignPublicKey
    message_size: int
    chunk_size: int
    total_size: int
  
  PubkeyEventStat = tuple
    pubkey: SignPublicKey
    count: int
  
  IPEventStat = tuple
    ip: string
    count: int

router myrouter:
  get "/ws":
    await request.handleWebsocket()
    result[0] = TCActionRaw
  
  get "/":
    var html = ""
    compileTemplateFile("index.nimja", baseDir = getScriptDir() / "templates", autoEscape = true, varname = "html")
    resp html
  
  get "/static/logo.png":
    resp logo_png
  
  get "/static/favicon.png":
    resp favicon_png
  
  get "/stats":
    if not request.isAdmin():
      responseHeaders.setHeader("WWW-Authenticate", "Basic realm=\"Relay Admin\"")
      resp Http401, "Unauthorized"

    let days_back = "-28 days"
    let datarange: PeriodRange = block:
      let row = relay.db.getRow(sql"""SELECT
        strftime('%Y-%W', datetime('now', ?)) AS a,
        strftime('%Y-%W') AS b""", days_back).get()
      (row[0].s, row[1].s)

    # total users
    let total_ips = relay.db.getRow(sql"SELECT coalesce(count(distinct ip), 0) FROM stats_event").get()[0].i
    let total_pubkeys = relay.db.getRow(sql"SELECT coalesce(count(distinct pubkey), 0) FROM stats_event").get()[0].i

    # total transfer
    let row = relay.db.getRow(sql"""
      SELECT
        coalesce(sum(data_in), 0) AS din,
        coalesce(sum(data_out), 0) AS dout
      FROM
        stats_transfer
      WHERE
        period >= ?
    """, datarange.a).get()
    let total_data_in = row[0].i.int
    let total_data_out = row[1].i.int
    
    # total stored
    let total_stored_note = relay.db.getRow(sql"SELECT coalesce(sum(length(data)), 0) FROM note").get()[0].i
    let total_stored_message = relay.db.getRow(sql"SELECT coalesce(sum(length(data)), 0) FROM message").get()[0].i
    let total_stored_chunk = relay.db.getRow(sql"SELECT coalesce(sum(length(val)), 0) FROM chunk").get()[0].i
    let total_stored = total_stored_note + total_stored_message + total_stored_chunk
    let num_note = relay.db.getRow(sql"SELECT coalesce(count(*), 0) FROM note").get()[0].i
    let num_message = relay.db.getRow(sql"SELECT coalesce(count(*), 0) FROM message").get()[0].i
    let num_chunk = relay.db.getRow(sql"SELECT coalesce(count(*), 0) FROM chunk").get()[0].i

    # top traffic by ip
    var traffic_by_ip: seq[TransferTotal]
    for row in relay.db.getAllRows(sql"""
      SELECT
        sum(coalesce(data_in, 0)) AS din,
        sum(coalesce(data_out, 0)) AS dout,
        sum(coalesce(data_in, 0)) + sum(coalesce(data_out, 0)) AS total,
        ip
      FROM
        stats_transfer
      WHERE
        period >= ?
      GROUP BY ip
      ORDER BY total DESC
      LIMIT 10
      """, datarange.a):
      traffic_by_ip.add((
        data_in: row[0].i.int,
        data_out: row[1].i.int,
        ip: row[3].s,
        pubkey: default(SignPublicKey),
        period: "",
      ))
    
    # top traffic by pubkey
    var traffic_by_pubkey: seq[TransferTotal]
    for row in relay.db.getAllRows(sql"""
      SELECT
        sum(coalesce(data_in, 0)) AS din,
        sum(coalesce(data_out, 0)) AS dout,
        sum(coalesce(data_in, 0)) + sum(coalesce(data_out, 0)) AS total,
        pubkey
      FROM
        stats_transfer
      WHERE
        period >= ?
        AND pubkey <> ''
      GROUP BY pubkey
      ORDER BY total DESC
      LIMIT 10
      """, datarange.a):
      traffic_by_pubkey.add((
        data_in: row[0].i.int,
        data_out: row[1].i.int,
        ip: "",
        pubkey: SignPublicKey.fromDB(row[3].b),
        period: "",
      ))
    
    # top storage by pubkey
    var storage_by_pubkey: seq[StorageStat]
    for row in relay.db.getAllRows(sql"""
        WITH msg AS (
            SELECT src, SUM(coalesce(LENGTH(data), 0)) AS msg_bytes
            FROM message
            GROUP BY src
        ),
        chunksize AS (
            SELECT src, SUM(coalesce(LENGTH(val), 0)) AS chunk_bytes
            FROM chunk
            GROUP BY src
        )
        SELECT
            COALESCE(m.src, c.src)               AS src,
            COALESCE(m.msg_bytes, 0)             AS msg_bytes,
            COALESCE(c.chunk_bytes, 0)           AS chunk_bytes,
            COALESCE(m.msg_bytes, 0) + COALESCE(c.chunk_bytes, 0) AS total_bytes
        FROM msg   AS m
        FULL OUTER JOIN chunksize AS c
            ON m.src = c.src
        ORDER BY total_bytes DESC
        LIMIT 10;
      """):
        storage_by_pubkey.add((
          pubkey: SignPublicKey.fromDb(row[0].b),
          message_size: row[1].i.int,
          chunk_size: row[2].i.int,
          total_size: row[3].i.int,
        ))
    
    # top events by pubkey
    var connects_by_pubkey: seq[PubkeyEventStat]
    for row in relay.db.getAllRows(sql"""
      SELECT
        pubkey,
        COALESCE(SUM(connect), 0)
      FROM
        stats_event
      WHERE
        period >= ?
        AND pubkey <> ''
      GROUP BY 1
      ORDER BY 2 DESC
      LIMIT 10
    """, datarange.a):
      connects_by_pubkey.add((
        pubkey: SignPublicKey.fromDb(row[0].b),
        count: row[1].i.int,
      ))
    
    var publish_by_pubkey: seq[PubkeyEventStat]
    for row in relay.db.getAllRows(sql"""
      SELECT
        pubkey,
        COALESCE(SUM(publish), 0)
      FROM
        stats_event
      WHERE
        period >= ?
        AND pubkey <> ''
      GROUP BY 1
      ORDER BY 2 DESC
      LIMIT 10
    """, datarange.a):
      publish_by_pubkey.add((
        pubkey: SignPublicKey.fromDb(row[0].b),
        count: row[1].i.int,
      ))
    
    var send_by_pubkey: seq[PubkeyEventStat]
    for row in relay.db.getAllRows(sql"""
      SELECT
        pubkey,
        COALESCE(SUM(send), 0)
      FROM
        stats_event
      WHERE
        period >= ?
        AND pubkey <> ''
      GROUP BY 1
      ORDER BY 2 DESC
      LIMIT 10
    """, datarange.a):
      send_by_pubkey.add((
        pubkey: SignPublicKey.fromDb(row[0].b),
        count: row[1].i.int,
      ))
    
    var store_by_pubkey: seq[PubkeyEventStat]
    for row in relay.db.getAllRows(sql"""
      SELECT
        pubkey,
        COALESCE(SUM(store), 0)
      FROM
        stats_event
      WHERE
        period >= ?
        AND pubkey <> ''
      GROUP BY 1
      ORDER BY 2 DESC
      LIMIT 10
    """, datarange.a):
      store_by_pubkey.add((
        pubkey: SignPublicKey.fromDb(row[0].b),
        count: row[1].i.int,
      ))

    var html = ""
    compileTemplateFile("stats.nimja", baseDir = getScriptDir() / "templates", autoEscape = true, varname = "html")
    resp html

proc main(database: string, port: Port, address = "127.0.0.1") =
  var L = newConsoleLogger()
  addHandler(L)
  info "Database: ", database
  var db = open(database, "", "", "")
  db.exec(sql"PRAGMA journal_mode=PERSIST")
  db.exec(sql"PRAGMA busy_timeout = 5000")
  db.exec(sql"PRAGMA synchronous = FULL")
  relay = newRelay[NetstringSocket](db)
  info &"Serving on {address}:{port.int}"
  let settings = newSettings(port=port, bindAddr=address)
  var jester = initJester(myrouter, settings=settings)
  jester.serve()

when isMainModule:
  import argparse
  var p = newParser:
    option("-d", "--database", default=some("brelay.sqlite"), help="Database")
    command("hashpassword"):
      help("Generate a hash for a password given on stdin")
      run:
        let password = stdin.readAll().strip()
        echo crypto_pwhash_str(password)
    command("server"):
      option("-p", "--port", default=some("9000"))
      option("-a", "--address", default=some("127.0.0.1"))
      run:
        main(opts.parentOpts.database, opts.port.parseInt.Port, opts.address)

  try:
    p.run()
  except UsageError as e:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)
  