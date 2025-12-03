import std/asyncdispatch
import std/base64
import std/json
import std/options
import std/os
import std/rdstdin
import std/strformat
import std/strutils

import ./sampleclient
import ./proto2

type
  CmdContext = object
    dst: SignPublicKey

proc serialize(pubkey: SignPublicKey): string =
  base64.encode(pubkey.string)

proc deserialize(pubkey: typedesc[SignPublicKey], x: string): SignPublicKey =
  base64.decode(x).SignPublicKey

proc serialize(keys: KeyPair): string =
  base64.encode($(%* {
    "pk": keys.pk.string,
    "sk": keys.sk.string,
  }))

proc deserialize(pair: typedesc[KeyPair], x: string): KeyPair =
  let j = base64.decode(x).parseJson()
  (j["pk"].getStr().SignPublicKey, j["sk"].getStr().SignSecretKey)

proc loadKeys(src: string): KeyPair =
  let parts = src.split(":", 1)
  case parts[0]
  of "keys":
    KeyPair.deserialize(parts[1])
  of "file":
    KeyPair.deserialize(readFile(parts[1]))
  else:
    raise ValueError.newException("Error loading keys")

proc saveKeys(keys: KeyPair, filename: string) =
  writeFile(filename, keys.serialize())

proc parseLine(line: string): seq[string] =
  result = @[]
  var i = 0
  var current = ""
  var inQuote = false
  var quoteChar = '\0'

  while i < line.len:
    let c = line[i]

    if inQuote:
      if c == quoteChar:
        inQuote = false
        result.add(current)
        current = ""
      else:
        current.add(c)
    else:
      if c in {'\'', '"'}:
        inQuote = true
        quoteChar = c
        if current.len > 0:
          result.add(current)
          current = ""
      elif c == ' ':
        if current.len > 0:
          result.add(current)
          current = ""
      elif c == '\\':
        inc(i)
        if i < line.len:
          current.add(line[i])
      else:
        current.add(c)
    inc(i)

  if current.len > 0:
    result.add(current)

  # Handle unclosed quote as literal
  if inQuote and current.len > 0:
    result.add(current)

proc use(i: var int, s: seq[string]): string =
  result = s[i]
  i.inc()

proc doCommand(client: NetstringClient, full: seq[string], ctx: var CmdContext) =
  let cmd = full[0]
  let args = full[1..^1]
  var i = 0
  case cmd
  of "post":
    let topic = i.use(args)
    let data = i.use(args)
    waitFor client.publishNote(topic, data)
    echo "posted ", topic
  of "fetch":
    let topic = i.use(args)
    let data = waitFor client.fetchNote(topic)
    echo data
  of "dst":
    if args.len == 0:
      ctx.dst = "".SignPublicKey
    else:
      ctx.dst = SignPublicKey.deserialize(i.use(args))
    echo "dst for future commands set to ", ctx.dst.serialize()
  of "send":
    var dst = ctx.dst
    if dst.string == "":
      dst = SignPublicKey.deserialize(i.use(args))
    let val = i.use(args)
    waitFor client.sendData(dst, val)
  of "recv":
    let data = waitFor client.getData()
    echo data
  of "store":
    var dst = ctx.dst
    if dst.string == "" or args.len >= 3:
      dst = SignPublicKey.deserialize(i.use(args))
      echo "Using key=" & dst.nice
    let key = i.use(args)
    let val = i.use(args)
    waitFor client.storeChunk(@[dst], key, val)
  of "get":
    var src = ctx.dst
    if src.string == "" or args.len >= 2:
      src = SignPublicKey.deserialize(i.use(args))
      echo "Using key=" & src.serialize
    let key = i.use(args)
    let odata = waitFor client.getChunk(src, key)
    if odata.isSome:
      echo odata.get()
    else:
      echo "(none)"
  of "has":
    var src = ctx.dst
    if src.string == "" or args.len >= 2:
      src = SignPublicKey.deserialize(i.use(args))
      echo "Using key=" & src.serialize
    let key = i.use(args)
    let res = waitFor client.hasChunk(src, key)
    echo $res
  of "help":
    echo """
  post TOPIC DATA
  fetch TOPIC
  dst PUBKEY
    Set the destination PUBKEY for future commands
  send [PUBKEY] DATA
  recv
  store [PUBKEY] KEY VAL
  get [PUBKEY] KEY
  has [PUBKEY] KEY
  help
    """
  else:
    echo "Unknown command ", cmd, " ", args  

proc main(url: string, keys: KeyPair, dst = "".SignPublicKey) =
  # authenticate
  echo "...pubkey: ", keys.pk.serialize
  echo "...connecting..."
  var client = newRelayClient(url, keys)
  var ctx: CmdContext
  ctx.dst = dst
  echo "...connected"
  while true:
    let line = readLineFromStdin(&"{ctx.dst.serialize}> ")
    if line == nil or line.strip() in ["exit", "quit"]:
      echo "...goodbye"
      break

    if line.strip() == "":
      continue

    let args = parseLine(line)
    try:
      client.doCommand(args, ctx)
    except IndexDefect:
      echo "ERROR: " & getCurrentExceptionMsg()
    except CatchableError:
      echo "ERROR: " & getCurrentExceptionMsg()

when isMainModule:
  import argparse

  var p = newParser:
    option("-u", "--url", default = some("ws://127.0.0.1:9000/ws"))
    option("-k", "--keys", default = some("file:client1.keys"))
    command("genkeys"):
      arg("filename")
      run:
        let keys = genkeys()
        keys.saveKeys(opts.filename)
    command("repl"):
      option("-d", "--dst", help = "Default destination")
      run:
        var dst = if opts.dst != "":
            SignPublicKey.deserialize(opts.dst)
          else:
            default(SignPublicKey)
        main(opts.parentOpts.url, keys = loadKeys(opts.parentOpts.keys), dst = dst)

  try:
    p.run(commandLineParams())
  except UsageError as e:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)