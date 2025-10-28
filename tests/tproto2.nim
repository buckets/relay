import std/deques
import std/logging
import std/options
import std/os
import std/strutils
import std/unittest

import lowdb/sqlite
import proto2

if getEnv("SHOW_LOGS") != "":
  var L = newConsoleLogger()
  addHandler(L)
else:
  echo "set SHOW_LOGS=something to see logs"


#---------------------------------
# In-memory TestClient
#---------------------------------
type
  TestClient* = ref object
    received: Deque[RelayMessage]
    pk: PublicKey
    sk: SecretKey

proc `$`*(tc: TestClient): string = $tc[]

proc newTestClient*(): TestClient =
  new(result)
  result.received = initDeque[RelayMessage]()

proc newTestClient*(keys: KeyPair): TestClient =
  new(result)
  result = newTestClient()
  result.pk = keys.pk
  result.sk = keys.sk

proc sendMessage*(c: var TestClient, msg: RelayMessage) =
  c.received.addLast(msg)

proc pop*(c: var TestClient): RelayMessage =
  c.received.popFirst()

#---------------------------------
# Test utilities
#---------------------------------
proc testRelay(): Relay[TestClient] =
  newRelay[TestClient](open(":memory:", "", "", ""))

proc pop(conn: var RelayConnection[TestClient]): RelayMessage =
  conn.sender.pop()

proc pop(conn: var RelayConnection[TestClient], expected: MessageKind): RelayMessage =
  try:
    result = conn.sender.pop()
  except IndexDefect:
    raise IndexDefect.newException("Error getting message of kind: " & $expected)
  doAssert result.kind == expected

proc msgCount(conn: var RelayConnection[TestClient]): int =
  conn.sender.received.len

proc pk(conn: var RelayConnection[TestClient]): PublicKey = conn.sender.pk
proc sk(conn: var RelayConnection[TestClient]): SecretKey = conn.sender.sk
proc keys(conn: var RelayConnection[TestClient]): KeyPair = (conn.sender.pk, conn.sender.sk)

proc authenticatedConn(relay: Relay, keys: KeyPair): RelayConnection[TestClient] =
  let client = newTestClient(keys)
  var conn = relay.initAuth(client)
  let who = conn.pop()
  doAssert who.kind == Who
  let sig = client.sk.sign(who.who_challenge)
  relay.handleCommand(conn, RelayCommand(kind: Iam, iam_signature: sig, iam_pubkey: client.pk))
  let ok = conn.pop()
  doAssert ok.kind == Okay
  doAssert ok.ok_cmd == Iam
  return conn

proc authenticatedConn(relay: Relay): RelayConnection[TestClient] =
  relay.authenticatedConn(genkeys())

#---------------------------------
# End of TestClient
#---------------------------------

suite "Auth":
  test "basic":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    
    checkpoint "who?"
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)
    check who.who_challenge != ""
    echo $who

    checkpoint "iam"
    let signature = aclient.sk.sign(who.who_challenge)
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_signature: signature, iam_pubkey: aclient.pk))
    discard alice.pop(Okay)

  test "iam twice":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    
    checkpoint "who?"
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)
    check who.who_challenge != ""

    checkpoint "iam"
    let signature = aclient.sk.sign(who.who_challenge)
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_signature: signature, iam_pubkey: aclient.pk))
    discard alice.pop(Okay)

    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_signature: signature, iam_pubkey: aclient.pk))
    check alice.pop().kind == Error

  test "iam invalid sig":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)

    let signature = aclient.sk.sign(who.who_challenge & "garbage")
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_signature: signature, iam_pubkey: aclient.pk))
    let err = alice.pop(Error)
    check err.err_cmd == Iam

suite "PublishNote":

  test "basic":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "sometopic",
      pub_data: "somedata",
    ))
    let ok = alice.pop(Okay)
    check ok.ok_cmd == PublishNote

    relay.handleCommand(bob, RelayCommand(
      kind: FetchNote,
      fetch_topic: "sometopic",
    ))
    let data = bob.pop(Note)
    check data.note_data == "somedata"
    check data.note_topic == "sometopic"

  test "fetch first":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: FetchNote,
      fetch_topic: "heyo",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "heyo",
      pub_data: "foo",
    ))
    check alice.pop(Okay).ok_cmd == PublishNote
    let note = alice.pop(Note)
    check note.note_data == "foo"
    check note.note_topic == "heyo"

  test "publish max size topic":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "h".repeat(RELAY_MAX_TOPIC_SIZE + 1),
      pub_data: "foo",
    ))
    block:
      let err = alice.pop(Error)
      check err.err_code == TooLarge
      check err.err_cmd == PublishNote

    relay.handleCommand(alice, RelayCommand(
      kind: FetchNote,
      fetch_topic: "a".repeat(RELAY_MAX_TOPIC_SIZE + 1),
    ))
    block:
      let err = alice.pop(Error)
      check err.err_code == TooLarge
      check err.err_cmd == FetchNote
  
  test "publish max size data":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "topic",
      pub_data: "a".repeat(RELAY_MAX_NOTE_SIZE + 1),
    ))
    let err = alice.pop(Error)
    check err.err_code == TooLarge
    check err.err_cmd == PublishNote

  test "expiration":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "topic",
      pub_data: "a",
    ))
    check alice.pop(Okay).ok_cmd == PublishNote

    skewTime(RELAY_NOTE_DURATION)
    skewTime(1)
    relay.handleCommand(alice, RelayCommand(
      kind: FetchNote,
      fetch_topic: "topic",
    ))
    check alice.msgCount == 0

  test "fetch note again":
    let relay = testRelay()
    var alice = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "sometopic",
      pub_data: "somedata",
    ))
    let ok = alice.pop(Okay)
    check ok.ok_cmd == PublishNote

    relay.handleCommand(alice, RelayCommand(
      kind: FetchNote,
      fetch_topic: "sometopic",
    ))
    let data = alice.pop(Note)
    check data.note_data == "somedata"

    relay.handleCommand(alice, RelayCommand(
      kind: FetchNote,
      fetch_topic: "sometopic",
    ))
    check alice.msgCount == 0
    
  test "sub then disconnect, the pub":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    relay.handleCommand(bob, RelayCommand(
      kind: FetchNote,
      fetch_topic: "foo",
    ))
    relay.disconnect(bob)

    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "foo",
      pub_data: "bar",
    ))

    var bob2 = relay.authenticatedConn(bob.keys)
    check bob2.msgCount == 0
    relay.handleCommand(bob2, RelayCommand(
      kind: FetchNote,
      fetch_topic: "foo"
    ))
    let data = bob2.pop(Note)
    check data.note_data == "bar"
    check data.note_topic == "foo"
  
  test "topic null byte":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "a\x00b",
      pub_data: "c\x00d",
    ))
    let ok = alice.pop(Okay)
    check ok.ok_cmd == PublishNote

    relay.handleCommand(bob, RelayCommand(
      kind: FetchNote,
      fetch_topic: "a\x00b",
    ))
    let data = bob.pop(Note)
    check data.note_data == "c\x00d"
    check data.note_topic == "a\x00b"

suite "data":

  test "basic":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[bob.pk],
      data: "hel\x00lo",
    ))

    let data = bob.pop(Data)
    check data.data_src == alice.pk
    check data.data_val == "hel\x00lo"

  test "store and forward":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob1 = relay.authenticatedConn()
    relay.disconnect(bob1)

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[bob1.pk],
      data: "hel\x00lo",
    ))

    var bob2 = relay.authenticatedConn(bob1.keys)
    let data = bob2.pop(Data)
    check data.data_src == alice.pk
    check data.data_val == "hel\x00lo"

  test "max data size":
    let relay = testRelay()
    var alice = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[alice.pk],
      data: "a".repeat(RELAY_MAX_MESSAGE_SIZE + 1),
    ))
    let err = alice.pop(Error)
    check err.err_code == TooLarge
    check err.err_cmd == SendData

  test "drop unknown key":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    let bobkeys = genkeys()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[bobkeys.pk],
      data: "a",
    ))
    check alice.msgCount == 0

    var bob = relay.authenticatedConn(bobkeys)
    check bob.msgCount == 0 # "Should not have stored the message"
  
  test "drop forgotten key":
    let relay = testRelay()
    var bob = relay.authenticatedConn()
    relay.disconnect(bob)

    skewTime(RELAY_PUBKEY_MEMORY_SECONDS + 1)
    var alice = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[bob.pk],
      data: "a",
    ))
    check alice.msgCount == 0

    var bob2 = relay.authenticatedConn(bob.keys)
    check bob2.msgCount == 0 # "Should not have stored the message"

  test "expiration":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    relay.disconnect(bob)

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[bob.pk],
      data: "hello",
    ))

    skewTime(RELAY_MESSAGE_DURATION + 1)
    var bob2 = relay.authenticatedConn(bob.keys)
    check bob2.msgCount == 0

  test "multiple dst":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    relay.disconnect(bob)

    var carl = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[bob.pk],
      data: "first",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[bob.pk, carl.pk],
      data: "second",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[carl.pk, bob.pk],
      data: "third",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      dst: @[carl.pk],
      data: "fourth",
    ))
    var bob2 = relay.authenticatedConn(bob.keys)
    check bob2.pop(Data).data_val == "first"
    check bob2.pop(Data).data_val == "second"
    check bob2.pop(Data).data_val == "third"
    check carl.pop(Data).data_val == "second"
    check carl.pop(Data).data_val == "third"
    check carl.pop(Data).data_val == "fourth"
    check relay.db.getRow(sql"SELECT id FROM message").isNone()
