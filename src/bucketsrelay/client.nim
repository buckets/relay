# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.
import std/base64
import std/logging
import std/options
import std/random
import std/strformat

import chronos; export chronos
import chronicles except debug, info, warn, error
export activeChroniclesStream, Record, activeChroniclesScope
import stew/byteutils
import websock/websock

import ./common
import ./netstring
import ./proto; export proto
import ./stringproto

const HEARTBEAT_INTERVAL = 50.seconds
const HEARTBEAT_JITTER = 1000

type
  ## RelayClient wraps a single websockets connection
  ## to a relay server. It will call things on
  ## `handler: T` to interact with your code.
  RelayClient*[T] = ref object
    keys: KeyPair
    wsopt: Option[WSSession]
    handler*: T
    username: string
    password: string
    verifyHostname: bool
    done*: Future[void]
    tasks*: seq[Future[void]]
    debugname*: string
  
  ClientLifeEventKind* = enum
    ConnectedToServer
    DisconnectedFromServer
  
  ClientLifeEvent* = ref object
    case kind*: ClientLifeEventKind
    of ConnectedToServer:
      discard
    of DisconnectedFromServer:
      discard
  
  RelayErrLoginFailed* = RelayErr
  RelayNotConnected* = RelayErr

proc newRelayClient*[T](keys: KeyPair, handler: T, username, password: string, verifyHostname = true): RelayClient[T] =
  new(result)
  result.keys = keys
  result.handler = handler
  result.username = username
  result.password = password
  result.verifyHostname = verifyHostname
  # result.done = newFuture[void]("newRelayClient done")
  result.debugname = "RelayClient" & nextDebugName()

proc logname*(client: RelayClient): string =
  "(" & client.debugname & ") "

proc `$`*(client: RelayClient): string = client.debugname

proc ws*(client: RelayClient): WSSession =
  if client.wsopt.isSome:
    client.wsopt.get()
  else:
    raise RelayNotConnected.newException("Not connected")

proc send(ws: WSSession, cmd: RelayCommand) {.async.} =
  ## Send a RelayCommand to the server
  await ws.send(nsencode(dumps(cmd)).toBytes, Opcode.Binary)

proc keepAliveLoop(client: RelayClient) {.async.} =
  ## Start a loop that periodically issues a ping to keep the
  ## connection alive
  try:
    while true:
      await sleepAsync(HEARTBEAT_INTERVAL + rand(HEARTBEAT_JITTER).milliseconds)
      if client.wsopt.isSome:
        let ws = client.wsopt.get()
        await ws.ping()
      else:
        break
  except CancelledError:
    discard
  except:
    error client.logname, "unexpected error in ws keepAliveLoop"

proc loop(client: RelayClient, authenticated: Future[void]): Future[void] {.async.} =
  var decoder = newNetstringDecoder()
  if client.wsopt.isSome():
    let ws = client.ws
    while ws.readyState != ReadyState.Closed:
      try:
        let buff = try:
            await ws.recvMsg()
          except Exception as exc:
            break
        if buff.len <= 0:
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
          try:
            await client.handler.handleEvent(ev, client)
          except:
            debug client.logname, "Error handling event ", $ev, " ", getCurrentExceptionMsg()
            raise
      except CancelledError:
        break
    debug client.logname, "closing..."
    client.wsopt = none[WSSession]()
    await ws.close()
    await client.handler.handleLifeEvent(ClientLifeEvent(
      kind: DisconnectedFromServer,
    ), client)

proc authHeaderHook*(username, password: string): Hook =
  ## Create a websock connection hook that adds Basic HTTP authentication
  ## to the websocket.
  new(result)
  result.append = proc(ctx: Hook, headers: var HttpTable): Result[void, string] =
    headers.add("Authorization", "Basic " & base64.encode(username & ":" & password))
    ok()

proc addHeadersHook(addheaders: HttpTable): Hook =
  new(result)
  result.append = proc(ctx: Hook, headers: var HttpTable): Result[void, string] =
    for key, val in addheaders.stringItems:
      headers.add(key, val)
    ok()

proc connect*(client: RelayClient, url: string) {.async.} =
  ## Connect and authenticate with a relay server. Returns
  ## after authentication succeeds.
  var uri = parseUri(url)
  if uri.scheme == "http":
    uri.scheme = "ws"
  elif uri.scheme == "https":
    uri.scheme = "wss"
  let
    hostname = uri.hostname
    port = if uri.port == "": "443" else: uri.port
    addresses = resolveTAddress(uri.hostname, port.parseInt.Port)
    hooks = @[
      authHeaderHook(client.username, client.password),
      addHeadersHook(HttpTable.init({
        "User-Agent": "buckets-relay client 1.0",
      })),
    ]
    tls = uri.scheme == "https" or uri.scheme == "wss" or port == "443"
  if addresses.len == 0:
    raise ValueError.newException(&"Unable to resolve {uri.hostname}")
  let address = addresses[0]
  try:
    let ws = if tls:
        var flags: set[TLSFlags]
        if not client.verifyHostname:
          flags.incl(TLSFlags.NoVerifyHost)
          flags.incl(TLSFlags.NoVerifyServerName)
        await WebSocket.connect(
          uri,
          protocols = @["proto"],
          flags = flags,
          hooks = hooks,
          version = WSDefaultVersion,
          frameSize = WSDefaultFrameSize,
          onPing = nil,
          onPong = nil,
          onClose = nil,
          rng = nil,
        )
      else:
        await WebSocket.connect(
          address,
          path = uri.path,
          hooks = hooks,
          hostName = hostname,
        )
    client.wsopt = some(ws)
  except WebSocketError as exc:
    let msg = getCurrentExceptionMsg()
    if "403" in msg and "Forbidden" in msg:
      raise RelayErrLoginFailed.newException("Failed initial authentication")
    else:
      raise exc
  await client.handler.handleLifeEvent(ClientLifeEvent(
    kind: ConnectedToServer,
  ), client)
  var authenticated = newFuture[void]("relay.client.dial.authenticated")
  client.done = client.loop(authenticated)
  let fut = client.keepAliveLoop()
  client.tasks.add(fut)
  await authenticated

proc connect*(client: RelayClient, pubkey: PublicKey) {.async, raises: [RelayNotConnected].} =
  ## Initiate a connection through the relay to the given public key
  await client.ws.send(RelayCommand(
    kind: Connect,
    conn_pubkey: pubkey,
  ))

proc sendData*(client: RelayClient, dest_pubkey: PublicKey, data: string) {.async, raises: [RelayNotConnected].} =
  ## Send data to a connection through the relay
  await client.ws.send(RelayCommand(
    kind: SendData,
    send_data: data,
    dest_pubkey: dest_pubkey,
  ))

proc disconnect*(client: RelayClient) {.async.} =
  ## Disconnect this client from the network
  if not client.done.isNil:
    await client.done.cancelAndWait()
  if client.wsopt.isSome:
    await client.wsopt.get().close()
    client.wsopt = none[WSSession]()
  for task in client.tasks:
    await task.cancelAndWait()

proc disconnect*(client: RelayClient, dest_pubkey: PublicKey) {.async.} =
  ## Disconnect this client from a remote client
  if client.wsopt.isSome:
    await client.wsopt.get().send(RelayCommand(
      kind: Disconnect,
      dcon_pubkey: dest_pubkey,
    ))
  