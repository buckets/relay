import std/asyncdispatch
import std/asynchttpserver
import std/logging
import std/strformat
import std/strutils

import nimja
import ws

const
  favicon_png = slurp"static/favicon.png"
  logo_png = slurp"static/logo.png"
  version = slurp"../CHANGELOG.md".split(" ")[1]
static:
  echo "version: ", version

var connections = newSeq[WebSocket]()

proc cb(req: Request) {.async, gcsafe.} =
  if req.url.path == "/":
    var html = ""
    compileTemplateFile("templates/index.html", baseDir = getScriptDir(), autoEscape = true, varname = "html")
    await req.respond(Http200, html)
  elif req.url.path == "/static/favicon.png":
    await req.respond(Http200, favicon_png)
  elif req.url.path == "/static/logo.png":
    await req.respond(Http200, logo_png)
  elif req.url.path == "/ws":
    try:
      var ws = await newWebSocket(req)
      connections.add ws
      # await ws.send("Welcome to simple chat server")
      while ws.readyState == Open:
        let packet = await ws.receiveStrPacket()
        # echo "Received packet: " & packet
        # for other in connections:
        #   if other.readyState == Open:
        #     asyncCheck other.send(packet)
    except WebSocketClosedError:
      echo "Socket closed. "
    except WebSocketProtocolMismatchError:
      echo "Socket tried to use an unknown protocol: ", getCurrentExceptionMsg()
    except WebSocketError:
      echo "Unexpected socket error: ", getCurrentExceptionMsg()
    await req.respond(Http200, "done")
  else:
    await req.respond(Http404, "Not found")

proc main(database: string, port: Port, address = "127.0.0.1") =
  var L = newConsoleLogger()
  addHandler(L)
  var server = newAsyncHttpServer()
  info &"Serving on {address}:{port.int}"
  waitFor server.serve(port, cb, address = address)

when isMainModule:
  import argparse
  var p = newParser:
    option("-d", "--database", help="Database")
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
  