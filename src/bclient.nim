# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/logging
import std/strformat
import std/strutils
import std/base64
import std/os

import chronos except debug, info, warn, error

import bucketsrelay/client
import bucketsrelay/proto
import bucketsrelay/asyncstdin

type
  SendHandler = ref object
    data: string
    sent: Future[void]

proc newSendHandler(data: string): SendHandler =
  new(result)
  result.data = data
  result.sent = newFuture[void]("newSendHandler")

proc handleEvent(handler: SendHandler, ev: RelayEvent, remote: RelayClient) {.async.} =
  try:
    case ev.kind
    of Connected:
      await remote.sendData(ev.conn_pubkey, handler.data)
      callSoon(proc(udata: pointer) =
        handler.sent.complete())
    else:
      discard
  except CancelledError:
    warn "SendHandler cancelled during event handling"
    raise

proc handleLifeEvent(handler: SendHandler, ev: ClientLifeEvent, remote: RelayClient) {.async.} =
  discard


type
  RecvHandler = ref object
    buf: string
    data: Future[string]

proc newRecvHandler(): RecvHandler =
  new(result)
  result.data = newFuture[string]("newRecvHandler")

proc handleEvent(handler: RecvHandler, ev: RelayEvent, remote: RelayClient) {.async.} =
  try:
    case ev.kind
    of Data:
      handler.buf.add(ev.data)
    of Disconnected:
      handler.data.complete(handler.buf)
    else:
      discard
  except CancelledError:
    warn "RecvHandler cancelled during event handling"
    raise

proc handleLifeEvent(handler: RecvHandler, ev: ClientLifeEvent, remote: RelayClient) {.async.} =
  discard

proc relaySend*(data: string, topubkey: PublicKey, relayurl: string, mykeys: KeyPair, username: string, password: string, verify = true): Future[void] {.async.} =
  debug &"Sending {data.len} bytes to {topubkey} via {relayurl} ..."
  var sh = newSendHandler(data)
  var client = newRelayClient(mykeys, sh, username, password, verifyHostname = verify)
  await client.connect(relayurl)
  await client.connect(topubkey)
  await sh.sent
  await client.disconnect()
  await client.done

proc relayReceive*(frompubkey: PublicKey, relayurl: string, mykeys: KeyPair, username: string, password: string, verify = true): Future[string] {.async.} =
  debug &"Receiving from {frompubkey} via {relayurl} ..."
  var rh = newRecvHandler()
  var client = newRelayClient(mykeys, rh, username, password, verifyHostname = verify)
  await client.connect(relayurl)
  await client.connect(frompubkey)
  result = await rh.data
  await client.disconnect()
  await client.done

type
  ChatHandler = ref object
    done: Future[void]

proc handleEvent(handler: ChatHandler, ev: RelayEvent, remote: RelayClient) {.async.} =
  case ev.kind
  of Data:
    stdout.write(ev.data)
    stdout.flushFile()
  of Disconnected:
    handler.done.complete()
  else:
    discard

proc handleLifeEvent(handler: ChatHandler, ev: ClientLifeEvent, remote: RelayClient) {.async.} =
  discard

proc chat(ch: ChatHandler, remote: RelayClient, remotePubkey: PublicKey) {.async.} =
  let reader = asyncStdinReader()
  while true:
    let inp = reader.read(1)
    await ch.done or inp
    if ch.done.completed:
      await inp.cancelAndWait()
      break
    else:
      let data = inp.read()
      await remote.sendData(remotePubkey, data)

proc relayChat*(otherpubkey: PublicKey, relayurl: string, mykeys: KeyPair, username: string, password: string, verify = true): Future[string] {.async.} =
  debug &"Attempting to chat with {otherpubkey} via {relayurl} ..."
  var ch = ChatHandler()
  ch.done = newFuture[void]()
  var client = newRelayClient(mykeys, ch, username, password, verifyHostname = verify)
  await client.connect(relayurl)
  await client.connect(otherpubkey)
  await ch.chat(client, otherpubkey)
  
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
    command("send"):
      help("Send stdin through the relay")
      option("-u", "--username", help="Relay username", env = "RELAY_USERNAME")
      option("-p", "--password", help="Relay password", env = "RELAY_PASSWORD")
      flag("-k", "--no-ssl-verify", help="Disable SSL verification")
      option("--local-secret", help="Path to local secret key", default=some("relay.key.secret"))
      option("--local-public", help="Path to local public key", default=some("relay.key.public"))
      arg("url", help="Relay URL to connect to. Should end in /relay")
      arg("public_key", help="Public key of remote client to connect to")
      run:
        newConsoleLogger(lvlAll, useStderr = true).addHandler()
        let keys = (
          readFile(opts.local_public).decode().PublicKey,
          readFile(opts.local_secret).decode().SecretKey,
        )
        let pubkey = opts.public_key.decode().PublicKey
        let data = stdin.readAll()
        waitFor relaySend(data, pubkey, relayurl = opts.url, mykeys = keys, username = opts.username, password = opts.password, verify = not opts.no_ssl_verify)
    command("receive"):
      help("Receive data through the relay to stdout")
      option("-u", "--username", help="Relay username", env = "RELAY_USERNAME")
      option("-p", "--password", help="Relay password", env = "RELAY_PASSWORD")
      flag("-k", "--no-ssl-verify", help="Disable SSL verification")
      option("--local-secret", help="Path to local secret key", default=some("relay.key.secret"))
      option("--local-public", help="Path to local public key", default=some("relay.key.public"))
      arg("url", help="Relay URL to connect to. Should end in /relay")
      arg("public_key", help="Public key of remote client to connect to")
      run:
        newConsoleLogger(lvlAll, useStderr = true).addHandler()
        let keys = (
          readFile(opts.local_public).decode().PublicKey,
          readFile(opts.local_secret).decode().SecretKey,
        )
        let pubkey = opts.public_key.decode().PublicKey
        echo waitFor relayReceive(pubkey, relayurl = opts.url, mykeys = keys, username = opts.username, password = opts.password, verify = not opts.no_ssl_verify)
    command("chat"):
      help("Open a symmetric chat stream with another client")
      option("-u", "--username", help="Relay username", env = "RELAY_USERNAME")
      option("-p", "--password", help="Relay password", env = "RELAY_PASSWORD")
      flag("-k", "--no-ssl-verify", help="Disable SSL verification")
      option("--local-secret", help="Path to local secret key", default=some("relay.key.secret"))
      option("--local-public", help="Path to local public key", default=some("relay.key.public"))
      flag("-v", "--verbose", help="Verbose logging")
      arg("url", help="Relay URL to connect to. Should end in /relay")
      arg("public_key", help="Public key of remote client to connect to")
      run:
        if opts.verbose:
          newConsoleLogger(lvlAll, useStderr = true).addHandler()
        let keys = (
          readFile(opts.local_public).decode().PublicKey,
          readFile(opts.local_secret).decode().SecretKey,
        )
        let pubkey = opts.public_key.decode().PublicKey
        echo waitFor relayChat(pubkey, relayurl = opts.url, mykeys = keys, username = opts.username, password = opts.password, verify = not opts.no_ssl_verify)
  try:
    p.run()
  except UsageError:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)
