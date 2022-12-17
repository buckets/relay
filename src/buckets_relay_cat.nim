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
  case ev.kind
  of Who:
    debug &"Server sent Who"
  of Authenticated:
    info &"Successfully authenticated!"
  of Connected:
    debug &"Connected to {ev.conn_pubkey.string.encode} ({ev.conn_id})"
    let data = stdin.readAll()
    remote.send(ev.conn_id, data)
  of Disconnected:
    debug &"Disconnected from {ev.dcon_pubkey.string.encode} ({ev.dcon_id})"
    handler.dc.complete()
  of Data:
    debug &"Received some data {ev.sender_id}: {ev.data.len}"
  of ErrorEvent:
    error &"Received error {ev.err_message}"
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
