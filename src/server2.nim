import std/asyncdispatch
import std/asynchttpserver
import std/logging
import std/strformat
import std/strutils
import std/deques

import nimja
import ws
import lowdb/sqlite

import ./proto2
import ./objs

type
  NetstringSocket* = ref object
    buf: string
    socket: WebSocket
  
  QueuedMessage* = tuple
    socket: NetstringSocket
    msg: RelayMessage

var relay: Relay[NetstringSocket] 
var message_queue = initDeque[QueuedMessage]()

proc newNetstringSocket*(sock: WebSocket): NetstringSocket =
  new(result)
  result.socket = sock

proc receiveString*(ns: NetstringSocket): Future[string] {.async.} =
  while true:
    try:
      return ns.buf.nschop()
    except IncompleteNetstring:
      discard
    let packet = await ns.socket.receiveStrPacket()
    ns.buf &= packet  

proc sendString*(ns: NetstringSocket, msg: string): Future[void] {.async.} =
  await ns.socket.send(nsencode(msg))

proc sendCommand*(ns: NetstringSocket, cmd: RelayCommand): Future[void] {.async.} =
  when LOG_COMMS:
    info "[client] -> " & $cmd
  await ns.sendString(cmd.serialize())

proc receiveCommand*(ns: NetstringSocket): Future[RelayCommand] {.async.} =
  let s = await ns.receiveString()
  return RelayCommand.deserialize(s)

proc receiveMessage*(ns: NetstringSocket): Future[RelayMessage] {.async.} =
  let s = await ns.receiveString()
  let res = RelayMessage.deserialize(s)
  when LOG_COMMS:
    info "[client] <- " & $res
  return res

proc sendMessage*(ns: NetstringSocket, msg: RelayMessage) {.async.} =
  await ns.sendString(msg.serialize())

proc sendMessage*(conn: RelayConnection[NetstringSocket], msg: RelayMessage) =
  message_queue.addLast((conn.sender, msg))

proc sendQueuedMessages*() {.async.} =
  while message_queue.len > 0:
    let (sock, msg) = message_queue.popFirst()
    await sock.sendMessage(msg)

proc handleWebsocket(req: Request) {.async, gcsafe.} =
  var ws = await newWebSocket(req)
  var ns = newNetstringSocket(ws)
  var conn = relay.initAuth(ns)
  await sendQueuedMessages()
  while ns.socket.readyState == Open:
    let cmd = try:
      await ns.receiveCommand()
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
    await sendQueuedMessages()
  relay.disconnect(conn)
  await req.respond(Http200, "done")

proc cb(req: Request) {.async, gcsafe.} =
  if req.url.path == "/ws":
    await req.handleWebsocket()
  else:
    await req.respond(Http404, "Not found")

proc main(database: string, port: Port, address = "127.0.0.1") =
  var L = newConsoleLogger()
  addHandler(L)
  info "Database: ", database
  var db = open(database, "", "", "")
  relay = newRelay[NetstringSocket](db)
  var server = newAsyncHttpServer()
  info &"Serving on {address}:{port.int}"
  waitFor server.serve(port, cb, address = address)

when isMainModule:
  import argparse
  var p = newParser:
    option("-d", "--database", default=some("brelay.sqlite"), help="Database")
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
  