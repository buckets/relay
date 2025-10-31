import std/asyncdispatch
import std/net
import std/options
import std/os
import std/osproc
import std/unittest

import ./util

import sampleclient
import server2
import proto2

import ws

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
      "c", "-d:testmode", "-o:" & bin, "src"/"server2.nim",
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
    ], options = {poStdErrToStdOut, poUsePath, poParentStreams}
  )

proc isPortOpen(port: Port): bool =
  discard

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

proc serverURL(): string =
  "ws://127.0.0.1:" & $TESTPORT & "/ws"

proc testClient(keys: KeyPair): NetstringSocket =
  let url = serverURL()
  newRelayClient(url, keys)

proc testClient(): NetstringSocket =
  testClient(genkeys())


suite "publishnote":

  test "basic":
    var alice = testClient()
    var bob = testClient()
    waitFor alice.publishNote("basic", "data")
    check (waitFor bob.fetchNote("basic")) == "data"
    var p = bob.fetchNote("basic")
    check p.finished == false
    waitFor alice.publishNote("basic", "again")
    check (waitFor p) == "again"

  test "duplicate":
    var alice = testClient()
    waitFor alice.publishNote("dupe", "data")
    expect(CatchableError):
      waitFor alice.publishNote("dupe", "data again")

suite "data":

  test "basic":
    var akeys = genkeys()
    var bkeys = genkeys()
    var alice = testClient(akeys)
    var bob = testClient(bkeys)
    waitFor alice.sendData(bkeys.pk, "hey, bob?")
    check (waitFor bob.getData()) == "hey, bob?"
    waitFor bob.sendData(akeys.pk, "hi, alice!")
    check (waitFor alice.getData()) == "hi, alice!"
  
  test "offline":
    var akeys = genkeys()
    var bkeys = genkeys()
    var alice = testClient(akeys)
    waitFor alice.sendData(bkeys.pk, "message \x01")
    waitFor alice.sendData(bkeys.pk, "message \x02")
    waitFor alice.sendData(bkeys.pk, "message \x00null")

    var bob = testClient(bkeys)
    check (waitFor bob.getData()) == "message \x01"
    check (waitFor bob.getData()) == "message \x02"
    check (waitFor bob.getData()) == "message \x00null"

suite "chunks":

  test "basic":
    var akeys = genkeys()
    var bkeys = genkeys()
    var ckeys = genkeys()
    var alice = testClient(akeys)
    var bob = testClient(bkeys)
    var carl = testClient(ckeys)
    waitFor alice.storeChunk(@[bkeys.pk], "chunk1", "data1")
    waitFor alice.storeChunk(@[bkeys.pk, ckeys.pk], "chunk2", "data2")
    waitFor alice.storeChunk(@[bkeys.pk], "chunk3", "data3")
    waitFor alice.storeChunk(@[bkeys.pk], "chunk3", "data3updated")

    check (waitFor bob.getChunk(akeys.pk, "chunk1")) == some("data1")
    check (waitFor bob.getChunk(akeys.pk, "chunk2")) == some("data2")
    check (waitFor bob.getChunk(akeys.pk, "chunk3")) == some("data3updated")
    check (waitFor bob.getChunk(akeys.pk, "chunk4")).isNone()

    check (waitFor carl.getChunk(akeys.pk, "chunk1")).isNone()
    check (waitFor carl.getChunk(akeys.pk, "chunk2")) == some("data2")
    check (waitFor carl.getChunk(akeys.pk, "chunk3")).isNone()
    check (waitFor carl.getChunk(akeys.pk, "chunk4")).isNone()

suite "invalid":
  
  test "malformed":
    let ws = waitFor newWebSocket(serverURL())
    waitFor ws.send("garbage")
    waitForPort(TESTPORT)

  test "too big":
    let ws = waitFor newWebSocket(serverURL())
    waitFor ws.send("123456789:foooooo")
    waitForPort(TESTPORT)

  test "RelayMessage":
    var keys = genkeys()
    let ws = waitFor newWebSocket(serverURL())
    let ns = newNetstringSocket(ws)
    let who = waitFor ns.receiveMessage()
    let answer = who.who_challenge.answer(keys.sk)
    waitFor ns.sendCommand(RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: keys.pk))
    let ok = waitFor ns.receiveMessage()
    checkpoint $ok
    check ok.kind == Okay
    
    waitFor ws.send(nsencode(serialize(RelayMessage(
      kind: Note,
      note_topic: "hey",
      note_data: "data",
    ))))
    waitFor sleepAsync(1000)

    var legit = testClient()
    waitFor legit.publishNote("something", "here")
    check (waitFor legit.fetchNote("something")) == "here"
    check server.running()
    waitForPort(TESTPORT)

server.terminate()
