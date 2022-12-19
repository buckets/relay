# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/logging
import std/strformat
import std/strutils
import std/base64
import std/os

import chronos

import relay/client
import relay/proto

type
  SendHandler = ref object
    data: string
    sent: Future[void]

proc newSendHandler(data: string): SendHandler =
  new(result)
  result.data = data
  result.sent = newFuture[void]("newSendHandler")

proc handleEvent(handler: SendHandler, ev: RelayEvent, remote: RelayClient) {.async.} =
  case ev.kind
  of Connected:
    await remote.sendData(ev.conn_pubkey, handler.data)
    handler.sent.complete()
    await remote.disconnect()
  else:
    discard

type
  RecvHandler = ref object
    buf: string
    data: Future[string]

proc newRecvHandler(): RecvHandler =
  new(result)
  result.data = newFuture[string]("newRecvHandler")

proc handleEvent(handler: RecvHandler, ev: RelayEvent, remote: RelayClient) {.async.} =
  case ev.kind
  of Data:
    handler.buf.add(ev.data)
  of Disconnected:
    handler.data.complete(handler.buf)
  else:
    discard

proc relaySend*(data: string, topubkey: PublicKey, relayurl: string, mykeys: KeyPair, username: string, password: string): Future[void] {.async.} =
  debug &"Sending {data.len} bytes to {topubkey} via {relayurl} ..."
  var sh = newSendHandler(data)
  var client = newRelayClient(mykeys, sh, username, password)
  await client.connect(relayurl)
  await client.connect(topubkey)
  await sh.sent
  await client.disconnect()

proc relayReceive*(frompubkey: PublicKey, relayurl: string, mykeys: KeyPair, username: string, password: string): Future[string] {.async.} =
  debug &"Receiving from {frompubkey} via {relayurl} ..."
  var rh = newRecvHandler()
  var client = newRelayClient(mykeys, rh, username, password)
  await client.connect(relayurl)
  await client.connect(frompubkey)
  result = await rh.data
  await client.disconnect()

  
when isMainModule:
  import argparse
  newConsoleLogger(lvlAll, useStderr = true).addHandler()
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
    command("send"):
      help("Send stdin through the relay")
      option("-u", "--username", help="Relay username", env = "RELAY_USERNAME")
      option("-p", "--password", help="Relay password", env = "RELAY_PASSWORD")
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
        let data = stdin.readAll()
        waitFor relaySend(data, pubkey, relayurl = opts.url, mykeys = keys, username = opts.username, password = opts.password)
    command("receive"):
      help("Receive data through the relay to stdout")
      option("-u", "--username", help="Relay username", env = "RELAY_USERNAME")
      option("-p", "--password", help="Relay password", env = "RELAY_PASSWORD")
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
        echo waitFor relayReceive(pubkey, relayurl = opts.url, mykeys = keys, username = opts.username, password = opts.password)
  try:
    p.run()
  except UsageError:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)
