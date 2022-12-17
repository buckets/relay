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

proc pop(client: StringClient): RelayEvent =
  doAssert client.received.len > 0, "Expected an event"
  result = client.received[0]
  client.received.del(0)

proc pop(client: StringClient, kind: EventKind): RelayEvent =
  result = client.pop()
  doAssert result.kind == kind, "Expected " & $kind & " but found " & $result

proc sendEvent(client: StringClient, ev: RelayEvent) =
  client.received.add(ev)

proc connect(relay: var Relay, keys = none[KeyPair]()): StringClient =
  var keys = keys
  if keys.isNone:
    keys = some(genkeys())
  var client = newClient()
  client.pk = keys.get().pk
  client.sk = keys.get().sk
  client.id = relay.add(client)
  let who = client.pop()
  let signature = sign(client.sk, who.who_challenge)
  relay.handleCommand(client.id, RelayCommand(kind: Iam, iam_signature: signature, iam_pubkey: client.pk))
  let ok = client.pop()
  result = client

test "basic":
  var relay = newRelay[StringClient]()
  let (pk, sk) = genkeys()
  let alice = newClient()
  
  checkpoint "who?"
  let alice_id = relay.add(alice)
  let who = alice.pop()
  check who.kind == Who
  check who.who_challenge != ""

  checkpoint "iam"
  let signature = sign(sk, who.who_challenge)
  relay.handleCommand(alice_id, RelayCommand(kind: Iam, iam_signature: signature, iam_pubkey: pk))
  let ok = alice.pop()
  check ok.kind == Authenticated

  checkpoint "connect"
  let bob = relay.connect()
  let bob_id = bob.id
  check bob.id != alice_id
  relay.handleCommand(alice_id, RelayCommand(kind: Connect, conn_pubkey: bob.pk))
  relay.handleCommand(bob_id, RelayCommand(kind: Connect, conn_pubkey: pk))
  let bconn = bob.pop()
  check bconn.kind == Connected
  check bconn.conn_pubkey.string == pk.string

  let aconn = alice.pop()
  check aconn.kind == Connected
  check aconn.conn_pubkey.string == bob.pk.string

  checkpoint "data"
  relay.handleCommand(bob_id, RelayCommand(kind: SendData, send_data: "hello, alice!", send_id: bconn.conn_id))
  let adata = alice.pop()
  check adata.kind == Data
  check adata.data == "hello, alice!"
  check adata.sender_id == aconn.conn_id
  
  relay.handleCommand(alice_id, RelayCommand(kind: SendData, send_data: "hello, bob!", send_id: aconn.conn_id))
  let bdata = bob.pop()
  check bdata.kind == Data
  check bdata.data == "hello, bob!"
  check bdata.sender_id == bconn.conn_id

test "multiple conns to same pubkey":
  var relay = newRelay[StringClient]()
  var alice = relay.connect()
  var bob = relay.connect()
  relay.handleCommand(alice.id, RelayCommand(kind: Connect, conn_pubkey: bob.pk))
  relay.handleCommand(bob.id, RelayCommand(kind: Connect, conn_pubkey: alice.pk))
  discard alice.pop(Connected)
  discard bob.pop(Connected)
  relay.handleCommand(bob.id, RelayCommand(kind: Connect, conn_pubkey: alice.pk))
  check bob.received.len == 0
  check alice.received.len == 0

test "no crosstalk":
  var relay = newRelay[StringClient]()
  var alice = relay.connect()
  var bob = relay.connect()
  var cathy = relay.connect()
  var dave = relay.connect()
  relay.handleCommand(alice.id, RelayCommand(kind: Connect, conn_pubkey: bob.pk))
  relay.handleCommand(bob.id, RelayCommand(kind: Connect, conn_pubkey: alice.pk))
  discard alice.pop(Connected)
  discard bob.pop(Connected)
  check cathy.received.len == 0
  check dave.received.len == 0
  relay.handleCommand(alice.id, RelayCommand(kind: Connect, conn_pubkey: dave.pk))
  relay.handleCommand(dave.id, RelayCommand(kind: Connect, conn_pubkey: alice.pk))
  discard alice.pop(Connected)
  discard dave.pop(Connected)
  relay.sendData(alice.id, bob.id, "hi, bob")
  check bob.pop(Data).data == "hi, bob"
  check cathy.received.len == 0
  check dave.received.len == 0

test "disconnect multiple times":
  var relay = newRelay[StringClient]()
  var alice = relay.connect()
  check relay.removeClient(alice.id) == true
  check relay.removeClient(alice.id) == false

test "disconnect, remove from remote client.connections":
  var relay = newRelay[StringClient]()
  var alice = relay.connect()
  var bob = relay.connect()
  relay.handleCommand(alice.id, RelayCommand(kind: Connect, conn_pubkey: bob.pk))
  relay.handleCommand(bob.id, RelayCommand(kind: Connect, conn_pubkey: alice.pk))
  discard alice.pop(Connected)
  discard bob.pop(Connected)
  check relay.removeClient(alice.id) == true
  let edcon = bob.pop(Disconnected)
  check edcon.dcon_pubkey.string == alice.pk.string
  check edcon.dcon_id == alice.id
  let bobclient = relay.testmode_clients()[bob.id]
  check bobclient.testmode_connections.len == 0

test "send data to invalid id":
  var relay = newRelay[StringClient]()
  var alice = relay.connect()
  relay.sendData(alice.id, 8, "testing?")
  discard alice.pop(ErrorEvent)
  relay.sendData(alice.id, alice.id, "feedback")
  discard alice.pop(ErrorEvent)
  

test "send data to unconnected id":
  var relay = newRelay[StringClient]()
  var alice = relay.connect()
  var bob = relay.connect()
  relay.sendData(alice.id, bob.id, "hello")
  discard alice.pop(ErrorEvent)
  check bob.received.len == 0

test "connect to self":
  var relay = newRelay[StringClient]()
  var alice = relay.connect()
  relay.handleCommand(alice.id, RelayCommand(kind: Connect, conn_pubkey: alice.pk))
  discard alice.pop(ErrorEvent)

test "not authenticated":
  var relay = newRelay[StringClient]()
  let (pk, sk) = genkeys()
  let alice = newClient()
  
  checkpoint "who?"
  let alice_id = relay.add(alice)
  discard alice.pop(Who)

  let bob = relay.connect()

  checkpoint "connect"
  relay.handleCommand(alice.id, RelayCommand(kind: Connect, conn_pubkey: bob.pk))
  discard alice.pop(ErrorEvent)
  check bob.received.len == 0

  checkpoint "send"
  relay.sendData(alice.id, bob.id, "something")
  discard alice.pop(ErrorEvent)
  check bob.received.len == 0

test "disconnect command":
  var relay = newRelay[StringClient]()
  var alice = relay.connect()
  var bob = relay.connect()
  relay.handleCommand(alice.id, RelayCommand(kind: Connect, conn_pubkey: bob.pk))
  relay.handleCommand(bob.id, RelayCommand(kind: Connect, conn_pubkey: alice.pk))
  discard alice.pop(Connected)
  discard bob.pop(Connected)

  relay.handleCommand(alice.id, RelayCommand(kind: Disconnect, dcon_id: bob.id))
  check bob.pop(Disconnected).dcon_id == alice.id
  check alice.pop(Disconnected).dcon_id == bob.id
