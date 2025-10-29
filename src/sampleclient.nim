import std/asyncdispatch
import std/base64
import std/json
import std/unittest

import ws

import ./objs
import ./proto2
import ./server2

proc saveKeys(filename: string, keys: KeyPair) =
  writeFile(filename, pretty(%* {
    "pk": base64.encode(keys.pk.string),
    "sk": base64.encode(keys.sk.string),
  }))

proc loadKeys(filename: string): KeyPair =
  let data = readFile(filename).parseJson
  (
    base64.decode(data["pk"].getStr()).PublicKey,
    base64.decode(data["sk"].getStr()).SecretKey,
  )

proc authenticatedWS(url: string, keys: KeyPair): NetstringSocket =
  let ws = waitFor newWebSocket(url)
  var ns = newNetstringSocket(ws)
  let who = waitFor ns.receiveMessage()
  let sig = keys.sk.sign(who.who_challenge)
  waitFor ns.sendCommand(RelayCommand(kind: Iam, iam_signature: sig, iam_pubkey: keys.pk))
  let ok = waitFor ns.receiveMessage()
  doAssert ok.kind == Okay, $ok
  return ns

proc publishNote(ns: NetstringSocket, topic: string, data: string) =
  waitFor ns.sendCommand(RelayCommand(
    kind: PublishNote,
    pub_topic: topic,
    pub_data: data,
  ))
  let res = waitFor ns.receiveMessage()
  if res.kind == Okay:
    discard
  elif res.kind == Error:
    raise ValueError.newException("Error publishing note: " & $res.err_code & " " & res.err_message)

proc batteryOfTests(url: string) =
  let alice = genkeys()
  let bob = genkeys()
  let ws_alice = authenticatedWS(url, alice)
  ws_alice.publishNote("topic", "data")
  try:
    ws_alice.publishNote("topic", "data")
    raise CatchableError.newException("Failed to raise an error")
  except ValueError:
    discard

when isMainModule:
  import argparse
  var p = newParser:
    option("-k", "--keyfile", default=some("client1.keys"))
    option("-u", "--url", default=some("ws://127.0.0.1:9000/ws"))
    command("genkeys"):
      run:
        saveKeys(opts.parentOpts.keyfile, genkeys())
    command("publishnote"):
      arg("topic")
      arg("data")
      run:
        let keys = loadKeys(opts.parentOpts.keyfile)
        let ws = authenticatedWS(opts.parentOpts.url, keys)
        ws.publishNote(opts.topic, opts.data)
    command("tests"):
      run:
        batteryOfTests(opts.parentOpts.url)
  try:
    p.run()
  except UsageError as e:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)
  