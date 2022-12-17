# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/asyncdispatch
import std/logging
import std/strformat
import std/strutils
import std/base64
import std/os

import relay/client
import relay/proto

type
  ConsoleClientHandler = ref object
    dc: Future[void]

proc newHandler(): ConsoleClientHandler =
  new(result)
  result.dc = newFuture[void]("ConsoleClientHandler")

proc handleEvent(handler: ConsoleClientHandler, ev: RelayEvent, remote: RelayClient) =
  debug "<" & ev.dbg
  case ev.kind
  of Who:
    discard
  of Authenticated:
    discard
  of Connected:
    discard
    let data = stdin.readAll()
    remote.sendData(ev.conn_pubkey, data)
  of Disconnected:
    discard
    handler.dc.complete()
  of Data:
    discard
  of ErrorEvent:
    discard
  stderr.flushFile()

proc connect(pubkey: PublicKey, url: string, keys: KeyPair, username: string, password: string) =
  try:
    newConsoleLogger(lvlAll, useStderr = true).addHandler()
    setStdIoUnbuffered()
    debug &"My pubkey: {keys.pk.string.encode}"
    var evhandler = newHandler()
    var client = newRelayClient(keys, evhandler, username, password)
    debug &"Dialing to {url} ..."
    waitFor client.dial(url)
    debug &"Connecting to {pubkey.string.encode} ..."
    client.connect(pubkey)
    runForever()
  finally:
    stderr.flushFile()
  
when isMainModule:
  import argparse
  var p = newParser:
    command("genkeys"):
      help("Generate a keypair")
      option("-p", "--public", help="Filename to save public key to", default=some("relay.key.public"))
      option("-s", "--secret", help="Filename to save secret key to", default=some("relay.key.secret"))
      run:
        var keys = genkeys()
        writeFile(opts.public, keys.pk.string.encode & "\n")
        echo "Wrote ", opts.public
        writeFile(opts.secret, keys.sk.string.encode & "\n")
        echo "Wrote ", opts.secret
        echo "Public key:"
        echo keys.pk.string.encode()
    command("connect"):
      help("Add a user")
      option("-u", "--username", help="Username", env = "RELAY_USERNAME")
      option("-p", "--password", help="Password. If not given, will prompt", env = "RELAY_PASSWORD")
      option("--local-secret", help="Path to local secret key", default=some("relay.key.secret"))
      option("--local-public", help="Path to local public key", default=some("relay.key.public"))
      arg("url", help="Relay URL to connect to")
      arg("public_key", help="Public key of remote client to connect to")
      run:
        let keys = (
          readFile(opts.local_public).decode().PublicKey,
          readFile(opts.local_secret).decode().SecretKey,
        )
        let pubkey = opts.public_key.decode().PublicKey
        connect(pubkey, url = opts.url, keys = keys, username = opts.username, password = opts.password)
  try:
    p.run()
  except UsageError:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)
