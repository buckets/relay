import std/asyncdispatch
import std/base64
import std/json
import std/sequtils

import argparse
import ws

import ./objs
import ./proto2
import ./server2

export KeyPair, genkeys

proc saveKeys(filename: string, keys: KeyPair) =
  writeFile(filename, pretty(%* {
    "pk": base64.encode(keys.pk.string),
    "sk": base64.encode(keys.sk.string),
  }))

proc serializeKeys*(keys: KeyPair): string =
  base64.encode($(%* {
    "pk": keys.pk.string,
    "sk": keys.sk.string,
  }))

proc deserializeKeys*(text: string): KeyPair =
  let data = base64.decode(text).parseJson()
  return (
    data["pk"].getStr().PublicKey,
    data["sk"].getStr().SecretKey,
  )

proc loadKeys(location: string): KeyPair =
  if location.startsWith("file:"):
    let parts = location.split(":", maxsplit = 1)
    let filename = parts[1]
    let data = readFile(filename).parseJson
    return (
      base64.decode(data["pk"].getStr()).PublicKey,
      base64.decode(data["sk"].getStr()).SecretKey,
    )
  elif location.startsWith("inline:"):
    let parts = location.split(":", maxsplit = 1)
    return deserializeKeys(parts[1])
  else:
    raise ValueError.newException("Invalid key location")

proc newWS*(url: string): NetstringSocket =
  let ws = waitFor newWebSocket(url)
  return newNetstringSocket(ws)

proc authenticatedWS*(url: string, keys: KeyPair): NetstringSocket =
  var ns = newWS(url)
  let who = waitFor ns.receiveMessage()
  let sig = keys.sk.sign(who.who_challenge)
  waitFor ns.sendCommand(RelayCommand(kind: Iam, iam_signature: sig, iam_pubkey: keys.pk))
  let ok = waitFor ns.receiveMessage()
  doAssert ok.kind == Okay, $ok
  return ns

proc publishNote*(ns: NetstringSocket, topic: string, data: string) =
  waitFor ns.sendCommand(RelayCommand(
    kind: PublishNote,
    pub_topic: topic,
    pub_data: data,
  ))
  let res = waitFor ns.receiveMessage()
  echo "publishNote res: ", $res
  if res.kind == Okay:
    discard
  elif res.kind == Error:
    raise ValueError.newException("Error publishing note: " & $res.err_code & " " & res.err_message)

proc fetchNote*(ns: NetstringSocket, topic: string): string =
  waitFor ns.sendCommand(RelayCommand(
    kind: FetchNote,
    fetch_topic: topic,
  ))
  let res = waitFor ns.receiveMessage()
  if res.kind == Note:
    return res.note_data
  else:
    raise ValueError.newException("No such note: " & topic)

proc cli*(args: openArray[string], outp = stdout) =
  var cliparser = newParser:
    option("-k", "--keys", default=some("file:client1.keys"))
    option("-u", "--url", default=some("ws://127.0.0.1:9000/ws"))
    command("genkeys"):
      arg("filename")
      run:
        saveKeys(opts.filename, genkeys())
    command("publishnote"):
      arg("topic")
      arg("data")
      run:
        let keys = loadKeys(opts.parentOpts.keys)
        let ws = authenticatedWS(opts.parentOpts.url, keys)
        ws.publishNote(opts.topic, opts.data)
    command("fetchnote"):
      arg("topic")
      run:
        let keys = loadKeys(opts.parentOpts.keys)
        let ws = authenticatedWS(opts.parentOpts.url, keys)
        outp.write(ws.fetchNote(opts.topic))
  try:
    cliparser.run(toSeq(args))
  except UsageError as e:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)

when isMainModule:
  cli(commandLineParams())  
  
  