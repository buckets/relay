# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import unittest
import asyncdispatch
import strutils
import ./util

import relay/client
import relay/server

type
  ClientHandler = ref object
    events: seq[RelayEvent]

proc handleEvent(handler: ClientHandler, ev: RelayEvent, remote: RelayClient) =
  handler.events.add(ev)

proc newClientHandler(): ClientHandler =
  new(result)

proc popEvent(client: ClientHandler, k: EventKind): Future[RelayEvent] {.async, gcsafe.} =
  ## Wait for and remove particular event type from the queue
  # Since this is just for tests, this does dumb polling
  var res: RelayEvent
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
      await sleepAsync(10)

test "basic":
  withinTmpDir:
    var server = newRelayServer("data.sqlite")
    server.listen(9001.Port, address="127.0.0.1")
    let user1 = server.register_user("alice", "password")
    let user2 = server.register_user("bob", "password")

    var c1h = newClientHandler()
    var keys1 = genkeys()
    var client1 = newRelayClient(keys1, c1h, "alice", "password")
    waitFor client1.dial("ws://127.0.0.1:9001/relay")

    var c2h = newClientHandler()
    var keys2 = genkeys()
    var client2 = newRelayClient(keys2, c2h, "bob", "password")
    waitFor client2.dial("ws://127.0.0.1:9001/relay")

    client1.connect(keys2.pk)
    client2.connect(keys1.pk)

    var atob = (waitFor c1h.popEvent(Connected)).conn_pubkey
    var btoa = (waitFor c2h.popEvent(Connected)).conn_pubkey
    check atob.string != ""
    check btoa.string != ""
    
    client1.sendData(atob, "hello")
    check (waitFor c2h.popEvent(Data)).data == "hello"
    client2.sendData(btoa, "a".repeat(4096))
    check (waitFor c1h.popEvent(Data)).data == "a".repeat(4096)
