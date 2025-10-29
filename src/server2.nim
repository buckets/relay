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
  echo "ns.socket.send      ", msg.nice
  await ns.socket.send(nsencode(msg))
  echo "ns.socket.send DONE ", msg.nice

proc sendCommand*(ns: NetstringSocket, cmd: RelayCommand): Future[void] {.async.} =
  echo "asyncCheck sendString      ", $cmd
  await ns.sendString(cmd.serialize())
  echo "asyncCheck sendString DONE ", $cmd

proc receiveCommand*(ns: NetstringSocket): Future[RelayCommand] {.async.} =
  let s = await ns.receiveString()
  return RelayCommand.deserialize(s)

proc sendMessage*(conn: RelayConnection[NetstringSocket], msg: RelayMessage) =
  echo "asyncCheck sendMessage      ", $msg
  asyncCheck conn.sender.sendString(msg.serialize())
  echo "asyncCheck sendMessage DONE ", $msg

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
  asyncCheck server.serve(port, cb, address = address)
  runForever()

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
  