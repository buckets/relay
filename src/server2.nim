import std/asyncdispatch
import std/asynchttpserver
import std/logging
import std/strformat
import std/strutils

import nimja
import ws
import lowdb/sqlite

import ./proto2
import ./objs

type
  NetstringSocket* = ref object
    buf: string
    socket: WebSocket

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
  ns.socket.send(nsencode(msg))

proc sendCommand*(ns: NetstringSocket, cmd: RelayCommand) =
  asyncCheck ns.sendString(cmd.serialize())

proc receiveCommand*(ns: NetstringSocket): Future[RelayCommand] {.async.} =
  let s = await ns.receiveString()
  return RelayCommand.deserialize(s)

proc sendMessage*(ns: NetstringSocket, msg: RelayMessage) =
  asyncCheck ns.sendString(msg.serialize())

proc receiveMessage*(ns: NetstringSocket): Future[RelayMessage] {.async.} =
  let s = await ns.receiveString()
  return RelayMessage.deserialize(s)

var relay: Relay[NetstringSocket] 

proc handleWebsocket(req: Request) {.async, gcsafe.} =
  var ws = await newWebSocket(req)
  var ns = newNetstringSocket(ws)
  var conn = relay.initAuth(ns)
  while ns.socket.readyState == Open:
    let cmd = try:
      await ns.receiveCommand()
    except WebSocketClosedError:
      break
    except WebSocketProtocolMismatchError:
      echo "Socket tried to use an unknown protocol: ", getCurrentExceptionMsg()
      break
    except WebSocketError:
      echo "Unexpected socket error: ", getCurrentExceptionMsg()
      break
    except CatchableError:
      echo "CatchableError: ", getCurrentExceptionMsg()
      break
    relay.handleCommand(conn, cmd)
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
  