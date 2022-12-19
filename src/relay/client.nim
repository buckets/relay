# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/base64
import std/logging
import std/options
import std/strformat

import chronos; export chronos
import chronicles; export chronicles
import stew/byteutils
import websock/websock

import ./netstring
import ./proto; export proto
import ./stringproto

type
  RelayClient*[T] = ref object
    keys: KeyPair
    wsopt: Option[WSSession]
    handler: T
    username: string
    password: string

proc newRelayClient*[T](keys: KeyPair, handler: T, username, password: string): RelayClient[T] =
  new(result)
  result.keys = keys
  result.handler = handler
  result.username = username
  result.password = password

proc ws*(client: RelayClient): WSSession =
  if client.wsopt.isSome:
    client.wsopt.get()
  else:
    raise ValueError.newException("No websocket")

proc send*(ws: WSSession, cmd: RelayCommand) {.async.} =
  await ws.send(nsencode(dumps(cmd)).toBytes, Opcode.Binary)

proc loop(client: RelayClient, authenticated: Future[void]) {.async.} =
  var decoder = newNetstringDecoder()
  if client.wsopt.isSome():
    let ws = client.ws
    while ws.readyState != ReadyState.Closed:
      let buff = await ws.recvMsg()
      if buff.len <= 0:
        TODO "How to handle 0 bytes?"
        break
      let data = string.fromBytes(buff)
      decoder.consume(data)
      while decoder.hasMessage():
        let ev = loadsRelayEvent(decoder.nextMessage())
        case ev.kind
        of Who:
          await ws.send(RelayCommand(
            kind: Iam,
            iam_signature: sign(client.keys.sk, ev.who_challenge),
            iam_pubkey: client.keys.pk,
          ))
        of Authenticated:
          authenticated.complete()
        else:
          discard
        await client.handler.handleEvent(ev, client)
  TODO "Handle end of loop"

proc authHeaderHook*(username, password: string): Hook =
  ## Create a websock connection hook that adds Basic HTTP authentication
  ## to the websocket.
  new(result)
  result.append = proc(ctx: Hook, headers: var HttpTable): Result[void, string] =
    headers.add("Authorization", "Basic " & base64.encode(username & ":" & password))
    ok()

proc connect*(client: RelayClient, url: string) {.async.} =
  ## Connect and authenticate with a relay server
  let
    uri = parseUri(url)
    address = (uri.hostname & ":" & $uri.port)
    authheaders = authHeaderHook(client.username, client.password)
  let ws = when defined tls:
      await WebSocket.connect(
        address,
        path = uri.path,
        secure = true,
        flags = {TLSFlags.NoVerifyHost, TLSFlags.NoVerifyServerName},
        hooks = @[authheaders],
      )
    else:
      await WebSocket.connect(
        address,
        path = uri.path,
        hooks = @[authheaders],
      )
  client.wsopt = some(ws)
  var authenticated = newFuture[void]("relay.client.dial.authenticated")
  asyncCheck client.loop(authenticated)
  TODO "when it's time, close the loop and close the websocket"
  await authenticated

proc connect*(client: RelayClient, pubkey: PublicKey) {.async.} =
  ## Initiate a connection through the relay to the given public key
  await client.ws.send(RelayCommand(
      kind: Connect,
      conn_pubkey: pubkey,
    ))

proc sendData*(client: RelayClient, dest_pubkey: PublicKey, data: string) {.async.} =
  ## Send data to a connection through the relay
  await client.ws.send(RelayCommand(
      kind: SendData,
      send_data: data,
      dest_pubkey: dest_pubkey,
    ))

proc disconnect*(client: RelayClient) {.async.} =
  ## Disconnect this client from the network
  if client.wsopt.isSome:
    await client.ws.close()
