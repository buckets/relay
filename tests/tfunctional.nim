import std/net
import std/unittest
import std/osproc
import std/os

import sampleclient

const TESTPORT = 12222.Port

proc startServer(port: Port): Process =
  let database = absolutePath(currentSourcePath().parentDir() / "func.sqlite")
  if database.fileExists:
    echo "removing ", database.relativePath(".")
    removeFile(database)
  
  let bin = absolutePath(currentSourcePath().parentDir() / "bin" / "server2")
  bin.parentDir.createDir()
  echo "compiling ", bin.relativePath(".")
  echo execProcess("nim",
    workingDir = currentSourcePath().parentDir().parentDir(),
    args = [
      "c", "-o:" & bin, "src"/"server2.nim",
    ],
    options = {poStdErrToStdOut, poUsePath}
  )
  echo "compiled ", bin.relativePath(".")
  
  startProcess(bin,
    workingDir = currentSourcePath().parentDir(),
    args = [
      "--database", database,
      "server",
      "--port", $port,
    ], options = {poStdErrToStdOut, poUsePath}
  )

proc waitForPort(port: Port) =
  while true:
    sleep(100)
    try:
      let socket = newSocket()
      socket.connect("127.0.0.1", port)
      socket.close()
      break
    except:
      echo "waiting for port ", $port
  echo "port open: ", $port

proc stop(p: Process) =
  p.terminate()

var server = startServer(TESTPORT)
waitForPort(TESTPORT)

proc runcli(keys: KeyPair, args: openArray[string]): string =
  var allargs = @[
    "--keys", "inline:" & serializeKeys(keys),
    "--url", "ws://127.0.0.1:" & $TESTPORT & "/ws",
  ]
  allargs.add(args)
  echo "> ", $args
  cli(allargs)

proc runcliq(keys: KeyPair, args: openArray[string]) =
  ## Run a command and discard output
  discard runcli(keys, args)

var alice = genkeys()
var bob = genkeys()
var carl = genkeys()

suite "publishnote":

  test "basic":
    runcliq(alice, ["publishnote", "basic", "data"])
    check runcli(bob, ["fetchnote", "basic"]) == "data"
    expect(CatchableError):
      runcliq(bob, ["fetchnote", "basic"])


  test "duplicate":
    runcliq(alice, ["publishnote", "topic", "data"])
    expect(CatchableError):
      runcliq(alice, ["publishnote", "topic", "data2"])

  

test "smoke":
  check true


server.terminate()