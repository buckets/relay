# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/unittest
import std/strutils

import ./util

import relay/client
import relay/server

type
  ClientHandler = ref object
    events: seq[RelayEvent]
    lifeEvents: seq[ClientLifeEvent]

proc handleEvent(handler: ClientHandler, ev: RelayEvent, remote: RelayClient) {.async.} =
  handler.events.add(ev)

proc handleLifeEvent(handler: ClientHandler, ev: ClientLifeEvent, remote: RelayClient) {.async.} =
  handler.lifeEvents.add(ev)

proc newClientHandler(): ClientHandler =
  new(result)

proc popEvent(client: ClientHandler, k: EventKind): Future[RelayEvent] {.async, gcsafe.} =
  ## Wait for and remove particular event type from the queue
  # Since this is just for tests, this does dumb polling
  var res: RelayEvent
  var delay = 10
  while true:
    var idx = -1
    for i,ev in client.events:
      if ev.kind == k:
        idx = i
        res = ev
        break
    if idx >= 0:
      client.events.del(idx)
      return res
    else:
      if delay > 1000:
        echo "Waiting for event: " & $k
      await sleepAsync(delay)
      delay += 100

proc popEvent(client: ClientHandler, k: ClientLifeEventKind): Future[ClientLifeEvent] {.async.} =
  var delay = 10
  while true:
    var idx = -1
    for i,ev in client.lifeEvents:
      if ev.kind == k:
        idx = i
        result = ev
        break
    if idx >= 0:
      client.lifeEvents.del(idx)
      return result
    else:
      if delay > 1000:
        echo "Waiting for event: " & $k
      await sleepAsync(delay)
      delay += 100

proc verified_user(rs: RelayServer, email: string, password = ""): int64 =
  result = rs.register_user(email, password)
  let token = rs.generate_email_verification_token(result)
  assert rs.use_email_verification_token(result, token) == true

test "basic":
  withinTmpDir:
    var server = newRelayServer(":memory:")
    server.start(initTAddress("127.0.0.1", 9001))
    defer:
      waitFor server.finish()
    let user1 = server.verified_user("alice", "password")
    let user2 = server.verified_user("bob", "password")

    var c1h = newClientHandler()
    var keys1 = genkeys()
    var client1 = newRelayClient(keys1, c1h, "alice", "password")
    waitFor client1.connect("ws://127.0.0.1:9001/v1/relay")
    discard waitFor c1h.popEvent(ConnectedToServer)

    var c2h = newClientHandler()
    var keys2 = genkeys()
    var client2 = newRelayClient(keys2, c2h, "bob", "password")
    waitFor client2.connect("ws://127.0.0.1:9001/v1/relay")
    discard waitFor c2h.popEvent(ConnectedToServer)

    waitFor client1.connect(keys2.pk)
    waitFor client2.connect(keys1.pk)

    var atob = (waitFor c1h.popEvent(Connected)).conn_pubkey
    var btoa = (waitFor c2h.popEvent(Connected)).conn_pubkey
    check atob.string != ""
    check btoa.string != ""
    
    waitFor client1.sendData(atob, "hello")
    check (waitFor c2h.popEvent(Data)).data == "hello"
    waitFor client2.sendData(btoa, "a".repeat(4096))
    check (waitFor c1h.popEvent(Data)).data == "a".repeat(4096)

    waitFor client1.disconnect(keys2.pk)
    waitFor client2.disconnect(keys2.pk)

    check (waitFor c1h.popEvent(Disconnected)).dcon_pubkey == keys2.pk
    check (waitFor c2h.popEvent(Disconnected)).dcon_pubkey == keys1.pk

test "NotConnected":
  withinTmpDir:
    var server = newRelayServer(":memory:")
    server.start(initTAddress("127.0.0.1", 9002))
    let user1 = server.verified_user("alice", "password")

    var ch = newClientHandler()
    var keys1 = genkeys()
    var client1 = newRelayClient(keys1, ch, "alice", "password")
    waitFor client1.connect("ws://127.0.0.1:9002/v1/relay")
    echo "Stopping relay server ..."
    waitFor server.finish()
    echo "Relay server stopped"
    for req in allHttpRequests:
      # req.stream.writer.tsource.close()
      req.stream.reader.tsource.close()
    echo "Closed stream"
    discard waitFor ch.popEvent(DisconnectedFromServer)
    expect RelayNotConnected:
      waitFor client1.connect("foobar".PublicKey)
    expect RelayNotConnected:
      waitFor client1.sendData("foobar".PublicKey, "some data")

test "wrong credentials":
  var server = newRelayServer(":memory:")
  server.start(initTAddress("127.0.0.1", 9003))
  defer:
    waitFor server.finish()
  let user1 = server.verified_user("alice", "password")

  var ch = newClientHandler()
  var keys1 = genkeys()
  var client1 = newRelayClient(keys1, ch, "alice", "wrongpassword")
  expect RelayErrLoginFailed:
    waitFor client1.connect("ws://127.0.0.1:9003/v1/relay")
