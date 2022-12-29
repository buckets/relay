# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import unittest
import os
import options
import tables
import sets
import logging

import relay/proto
import libsodium/sodium
import ./util

type
  KeyPair = tuple
    pk: PublicKey
    sk: SecretKey
  StringClient = ref object
    id: int
    received: seq[RelayEvent]
    pk: PublicKey
    sk: SecretKey

proc newClient(): StringClient =
  new(result)
  result.received = newSeq[RelayEvent]()

proc popEvent(client: StringClient): RelayEvent =
  doAssert client.received.len > 0, "Expected an event"
  result = client.received[0]
  client.received.del(0)

proc popEvent(client: StringClient, kind: EventKind): RelayEvent =
  result = client.popEvent()
  doAssert result.kind == kind, "Expected " & $kind & " but found " & $result

proc sendEvent(client: StringClient, ev: RelayEvent) =
  client.received.add(ev)

proc popEvent(conn: RelayConnection[StringClient]): RelayEvent =
  conn.sender.popEvent()

proc popEvent(conn: RelayConnection[StringClient], kind: EventKind): RelayEvent =
  conn.sender.popEvent(kind)

proc mkConnection(relay: var Relay, keys = none[KeyPair](), channel = ""): RelayConnection[StringClient] =
  var keys = keys
  if keys.isNone:
    keys = some(genkeys())
  var client = newClient()
  client.pk = keys.get().pk
  client.sk = keys.get().sk
  var conn = relay.initAuth(client, channel = channel)
  let who = client.popEvent()
  let signature = sign(client.sk, who.who_challenge)
  relay.handleCommand(conn, RelayCommand(kind: Iam, iam_signature: signature, iam_pubkey: client.pk))
  let ok = client.popEvent()
  result = conn

template sendData*(relay: var Relay, src: RelayConnection, dst: PublicKey, data: string) =
  relay.handleCommand(src, RelayCommand(kind: SendData, send_data: data, dest_pubkey: dst))

test "basic":
  var relay = newRelay[StringClient]()
  let (pk, sk) = genkeys()
  var aclient = newClient()
  aclient.pk = pk
  aclient.sk = sk
  
  checkpoint "who?"
  var alice = relay.initAuth(aclient)
  let who = alice.popEvent()
  check who.kind == Who
  check who.who_challenge != ""

  checkpoint "iam"
  let signature = sign(sk, who.who_challenge)
  relay.handleCommand(alice, RelayCommand(kind: Iam, iam_signature: signature, iam_pubkey: pk))
  let ok = alice.popEvent()
  check ok.kind == Authenticated

  checkpoint "connect"
  let bob = relay.mkConnection()
  check bob.pubkey != alice.pubkey
  relay.handleCommand(alice, RelayCommand(kind: Connect, conn_pubkey: bob.pubkey))
  relay.handleCommand(bob, RelayCommand(kind: Connect, conn_pubkey: alice.pubkey))
  block:
    let ev = bob.popEvent()
    check ev.kind == Connected
    check ev.conn_pubkey == alice.pubkey

  block:
    let ev = alice.popEvent()
    check ev.kind == Connected
    check ev.conn_pubkey == bob.pubkey

  checkpoint "data"
  relay.handleCommand(bob, RelayCommand(kind: SendData, send_data: "hello, alice!", dest_pubkey: alice.pubkey))
  let adata = alice.popEvent()
  check adata.kind == Data
  check adata.data == "hello, alice!"
  check adata.sender_pubkey == bob.pubkey
  
  relay.handleCommand(alice, RelayCommand(kind: SendData, send_data: "hello, bob!", dest_pubkey: bob.pubkey))
  let bdata = bob.popEvent()
  check bdata.kind == Data
  check bdata.data == "hello, bob!"
  check bdata.sender_pubkey == alice.pubkey

test "multiple conns to same pubkey":
  var relay = newRelay[StringClient]()
  var alice = relay.mkConnection()
  var bob = relay.mkConnection()
  relay.handleCommand(alice, RelayCommand(kind: Connect, conn_pubkey: bob.pubkey))
  relay.handleCommand(bob, RelayCommand(kind: Connect, conn_pubkey: alice.pubkey))
  discard alice.popEvent(Connected)
  discard bob.popEvent(Connected)
  relay.handleCommand(bob, RelayCommand(kind: Connect, conn_pubkey: alice.pubkey))
  check bob.sender.received.len == 0
  check alice.sender.received.len == 0

test "no crosstalk":
  var relay = newRelay[StringClient]()
  var alice = relay.mkConnection()
  var bob = relay.mkConnection()
  var cathy = relay.mkConnection()
  var dave = relay.mkConnection()
  relay.handleCommand(alice, RelayCommand(kind: Connect, conn_pubkey: bob.pubkey))
  relay.handleCommand(bob, RelayCommand(kind: Connect, conn_pubkey: alice.pubkey))
  discard alice.popEvent(Connected)
  discard bob.popEvent(Connected)
  check cathy.sender.received.len == 0
  check dave.sender.received.len == 0
  relay.handleCommand(alice, RelayCommand(kind: Connect, conn_pubkey: dave.pubkey))
  relay.handleCommand(dave, RelayCommand(kind: Connect, conn_pubkey: alice.pubkey))
  discard alice.popEvent(Connected)
  discard dave.popEvent(Connected)
  relay.sendData(alice, bob.pubkey, "hi, bob")
  check bob.popEvent(Data).data == "hi, bob"
  check cathy.sender.received.len == 0
  check dave.sender.received.len == 0

test "disconnect multiple times":
  var relay = newRelay[StringClient]()
  var alice = relay.mkConnection()
  relay.removeConnection(alice)
  relay.removeConnection(alice)

test "disconnect, remove from remote client.connections":
  var relay = newRelay[StringClient]()
  var alice = relay.mkConnection()
  var bob = relay.mkConnection()
  relay.handleCommand(alice, RelayCommand(kind: Connect, conn_pubkey: bob.pubkey))
  relay.handleCommand(bob, RelayCommand(kind: Connect, conn_pubkey: alice.pubkey))
  discard alice.popEvent(Connected)
  discard bob.popEvent(Connected)
  relay.removeConnection(alice)
  let edcon = bob.popEvent(Disconnected)
  check edcon.dcon_pubkey == alice.pubkey
  let bobclient = relay.testmode_conns()[bob.pubkey]
  check bobclient.testmode_conns.len == 0

test "send data to invalid id":
  var relay = newRelay[StringClient]()
  var alice = relay.mkConnection()
  relay.sendData(alice, "goober".PublicKey, "testing?")
  discard alice.popEvent(ErrorEvent)
  relay.sendData(alice, alice.pubkey, "feedback")
  discard alice.popEvent(ErrorEvent)

test "send data to unconnected id":
  var relay = newRelay[StringClient]()
  var alice = relay.mkConnection()
  var bob = relay.mkConnection()
  relay.sendData(alice, bob.pubkey, "hello")
  discard alice.popEvent(ErrorEvent)
  check bob.sender.received.len == 0

test "connect to self":
  var relay = newRelay[StringClient]()
  var alice = relay.mkConnection()
  relay.handleCommand(alice, RelayCommand(kind: Connect, conn_pubkey: alice.pubkey))
  discard alice.popEvent(ErrorEvent)

test "not authenticated":
  var relay = newRelay[StringClient]()
  let (pk, sk) = genkeys()
  let aclient = newClient()
  
  checkpoint "who?"
  var alice = relay.initAuth(aclient)
  discard alice.popEvent(Who)

  let bob = relay.mkConnection()

  checkpoint "connect"
  relay.handleCommand(alice, RelayCommand(kind: Connect, conn_pubkey: bob.pubkey))
  discard alice.popEvent(ErrorEvent)
  check bob.sender.received.len == 0

  checkpoint "send"
  relay.sendData(alice, bob.pubkey, "something")
  discard alice.popEvent(ErrorEvent)
  check bob.sender.received.len == 0

test "disconnect command":
  var relay = newRelay[StringClient]()
  var alice = relay.mkConnection()
  var bob = relay.mkConnection()
  relay.handleCommand(alice, RelayCommand(kind: Connect, conn_pubkey: bob.pubkey))
  relay.handleCommand(bob, RelayCommand(kind: Connect, conn_pubkey: alice.pubkey))
  discard alice.popEvent(Connected)
  discard bob.popEvent(Connected)

  relay.handleCommand(alice, RelayCommand(kind: Disconnect, dcon_pubkey: bob.pubkey))
  check bob.popEvent(Disconnected).dcon_pubkey == alice.pubkey
  check alice.popEvent(Disconnected).dcon_pubkey == bob.pubkey

test "pub/sub":
  var relay = newRelay[StringClient]()
  var alice = relay.mkConnection(channel = "alicenbob")
  var bob = relay.mkConnection(channel = "alicenbob")
  block:
    let ev = alice.popEvent(Entered)
    check ev.entered_pubkey == bob.pubkey
  block:
    let ev = bob.popEvent(Entered)
    check ev.entered_pubkey == alice.pubkey
  relay.removeConnection(alice)
  block:
    let ev = bob.popEvent(Exited)
    check ev.exited_pubkey == alice.pubkey
