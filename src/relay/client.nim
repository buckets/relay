# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/asyncdispatch
import std/base64
import std/logging
import std/options
import std/strformat

import ../vend/ws/ws
import protocols/netstring
import ./proto; export proto
import ./stringproto

type
  RelayClient*[T] = ref object
    keys: KeyPair
    wsopt: Option[WebSocket]
    handler: T
    username: string
    password: string

proc newRelayClient*[T](keys: KeyPair, handler: T, username, password: string): RelayClient[T] =
  new(result)
  result.keys = keys
  result.handler = handler
  result.username = username
  result.password = password

proc ws*(client: RelayClient): WebSocket =
  if client.wsopt.isSome:
    client.wsopt.get()
  else:
    raise ValueError.newException("No websocket")

proc loop(client: RelayClient, authenticated: Future[void]) {.async.} =
  var decoder = newNetstringDecoder()
  while client.wsopt.isSome():
    let ws = client.ws
    while ws.readyState == Open:
      let data = await ws.receiveStrPacket()
      decoder.consume(data)
      while decoder.hasMessage():
        let ev = loadsRelayEvent(decoder.nextMessage())
        # echo "client: got event ", $ev
        case ev.kind
        of Who:
          await ws.send(nsencode(dumps(
            RelayCommand(
              kind: Iam,
              iam_signature: sign(client.keys.sk, ev.who_challenge),
              iam_pubkey: client.keys.pk,
            )
          )))
        of Authenticated:
          authenticated.complete()
        else:
          discard
        client.handler.handleEvent(ev, client)
    warn "relay/client: ws not open"
  warn "relay/client: end of loop"

proc dial*(client: RelayClient, url: string) {.async.} =
  ## Connect and authenticate with a relay server
  info &"relay/client: dialing {url} ..."
  var ws = await newWebSocket(url, extraHeaders = @[
    ("Authorization", "Basic " & base64.encode(client.username & ":" & client.password)),
  ])
  info &"relay/client: websocket connected"
  client.wsopt = some(ws)
  var authenticated = newFuture[void]("relay.client.dial.authenticated")
  asyncCheck client.loop(authenticated)
  TODO "when it's time, close the loop and close the websocket"
  await authenticated

proc connect*(client: RelayClient, pubkey: PublicKey) =
  ## Initiate a connection through the relay to the given public key
  asyncCheck client.ws.send(nsencode(dumps(
    RelayCommand(
      kind: Connect,
      conn_pubkey: pubkey,
    )
  )))

proc send*(client: RelayClient, client_id: int, data: string) =
  ## Send data to a connection through the relay
  asyncCheck client.ws.send(nsencode(dumps(
    RelayCommand(
      kind: SendData,
      send_data: data,
      send_id: client_id,
    )
  )))