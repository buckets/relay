import std/deques
import std/logging
import std/options
import std/os
import std/strutils
import std/unittest

import lowdb/sqlite
import bucketsrelay/v2/proto2

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
    pk: SignPublicKey
    sk: SignSecretKey

proc `$`*(tc: TestClient): string = $tc[]

proc newTestClient*(): TestClient =
  new(result)
  result.received = initDeque[RelayMessage]()

proc newTestClient*(keys: KeyPair): TestClient =
  new(result)
  result = newTestClient()
  result.pk = keys.pk
  result.sk = keys.sk

proc sendMessage*(conn: RelayConnection[TestClient], msg: RelayMessage) =
  when LOG_COMMS:
    info "[" & conn.pubkey.abbr & "] <- " & $msg
  conn.sender.received.addLast(msg)

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
    raise IndexDefect.newException("No message found while expecting kind: " & $expected)
  doAssert result.kind == expected, "Expected " & $expected & " but got " & $result

proc msgCount(conn: var RelayConnection[TestClient]): int =
  conn.sender.received.len

proc pk(conn: var RelayConnection[TestClient]): SignPublicKey = conn.sender.pk
proc sk(conn: var RelayConnection[TestClient]): SignSecretKey = conn.sender.sk
proc keys(conn: var RelayConnection[TestClient]): KeyPair = (conn.sender.pk, conn.sender.sk)

proc anonConn(relay: Relay): RelayConnection[TestClient] =
  let client = newTestClient(genkeys())
  var conn = relay.initAuth(client)
  return conn

proc authenticatedConn(relay: Relay, keys: KeyPair): RelayConnection[TestClient] =
  let client = newTestClient(keys)
  var conn = relay.initAuth(client)
  let who = conn.pop()
  doAssert who.kind == Who
  let answer = who.who_challenge.answer(client.sk)
  relay.handleCommand(conn, RelayCommand(
    kind: Iam,
    resp_id: 1,
    iam_answer: answer,
    iam_pubkey: client.pk
  ))
  let ok = conn.pop()
  doAssert ok.kind == Okay
  doAssert ok.ok_cmd == Iam
  doAssert ok.resp_id == 1
  return conn

proc authenticatedConn(relay: Relay): RelayConnection[TestClient] =
  relay.authenticatedConn(genkeys())

#---------------------------------
# End of TestClient
#---------------------------------

suite "auth":
  test "basic":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    
    checkpoint "who?"
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)
    check who.who_challenge != default(Challenge)
    checkpoint $who

    checkpoint "iam"
    let answer = who.who_challenge.answer(aclient.sk)
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: aclient.pk))
    discard alice.pop(Okay)

  test "iam twice":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    
    checkpoint "who?"
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)
    check who.who_challenge != default(Challenge)

    checkpoint "iam"
    let answer = who.who_challenge.answer(aclient.sk)
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: aclient.pk))
    discard alice.pop(Okay)

    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: aclient.pk))
    check alice.pop().kind == Error

  test "iam invalid answer":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)

    let answer = generateChallenge().answer(aclient.sk)
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: aclient.pk))
    let err = alice.pop(Error)
    check err.err_cmd == Iam
  
  test "iam invalid signature":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)

    var bobkeys = genkeys()
    let answer = generateChallenge().answer(bobkeys.sk)
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: aclient.pk))
    let err = alice.pop(Error)
    check err.err_cmd == Iam
  
  test "invalid opslimit":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)

    let answer = generateChallenge(opslimit = who.who_challenge.opslimit - 1).answer(aclient.sk)
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: aclient.pk))
    let err = alice.pop(Error)
    check err.err_cmd == Iam

  test "invalid memlimit":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)

    let answer = generateChallenge(memlimit = who.who_challenge.memlimit - 32).answer(aclient.sk)
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: aclient.pk))
    let err = alice.pop(Error)
    check err.err_cmd == Iam
  
  test "invalid bits":
    let relay = testRelay()
    let aclient = newTestClient(genkeys())
    
    var alice = relay.initAuth(aclient)
    let who = alice.pop(Who)

    let answer = generateChallenge(bits = who.who_challenge.bits - 1).answer(aclient.sk)
    relay.handleCommand(alice, RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: aclient.pk))
    let err = alice.pop(Error)
    check err.err_cmd == Iam

suite "notes":

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
  
  test "same topic":
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

    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "sometopic",
      pub_data: "new data",
    ))
    let err = alice.pop(Error)
    check err.err_cmd == PublishNote

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
      resp_id: 34,
      fetch_topic: "heyo",
    ))
    let err = alice.pop(Error)
    check err.err_cmd == FetchNote
    check err.err_code == NotFound
    check err.resp_id == 34

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

  when not defined(release):
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
      let err = alice.pop(Error)
      check err.err_cmd == FetchNote
      check err.err_code == NotFound

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
    let err = alice.pop(Error)
    check err.err_cmd == FetchNote
    check err.err_code == NotFound
    
  test "sub then disconnect, the pub":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    relay.handleCommand(bob, RelayCommand(
      kind: FetchNote,
      fetch_topic: "foo",
    ))
    let err = bob.pop(Error)
    check err.err_cmd == FetchNote
    check err.err_code == NotFound
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
  
  test "max notes":
    var relay = testRelay()
    var alice = relay.authenticatedConn()
    for i in 0..<RELAY_MAX_NOTES:
      relay.handleCommand(alice, RelayCommand(
        kind: PublishNote,
        pub_topic: "topic" & $i,
        pub_data: "data",
      ))
      let ok = alice.pop(Okay)
      check ok.ok_cmd == PublishNote
    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "lasttopic",
      pub_data: "data",
    ))
    let err = alice.pop(Error)
    check err.err_cmd == PublishNote
    check err.err_code == StorageLimitExceeded

suite "data":

  test "basic":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_dst: @[bob.pk],
      send_val: "hel\x00lo",
    ))

    let data = bob.pop(Data)
    check data.data_key == ""
    check data.data_src == alice.pk
    check data.data_val == "hel\x00lo"
  
  test "basic w/ key":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "foom",
      send_dst: @[bob.pk],
      send_val: "hel\x00lo",
    ))

    let data = bob.pop(Data)
    check data.data_key == "foom"
    check data.data_src == alice.pk
    check data.data_val == "hel\x00lo"

  test "store and forward":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob1 = relay.authenticatedConn()
    relay.disconnect(bob1)

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_dst: @[bob1.pk],
      send_val: "hel\x00lo",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_dst: @[bob1.pk],
      send_val: "foo",
      send_key: "bar",
    ))

    var bob2 = relay.authenticatedConn(bob1.keys)
    block:
      let data = bob2.pop(Data)
      check data.data_key == ""
      check data.data_src == alice.pk
      check data.data_val == "hel\x00lo"
    block:
      let data = bob2.pop(Data)
      check data.data_key == "bar"
      check data.data_src == alice.pk
      check data.data_val == "foo"

  test "max data size":
    let relay = testRelay()
    var alice = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_dst: @[alice.pk],
      send_val: "a".repeat(RELAY_MAX_MESSAGE_SIZE + 1),
    ))
    let err = alice.pop(Error)
    check err.err_code == TooLarge
    check err.err_cmd == SendData
  
  test "max key size":
    let relay = testRelay()
    var alice = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "a".repeat(RELAY_MAX_KEY_SIZE + 1),
      send_dst: @[alice.pk],
      send_val: "a",
    ))
    let err = alice.pop(Error)
    check err.err_code == TooLarge
    check err.err_cmd == SendData

  when not defined(release):
    test "expiration":
      let relay = testRelay()
      var alice = relay.authenticatedConn()
      var bob = relay.authenticatedConn()
      relay.disconnect(bob)

      relay.handleCommand(alice, RelayCommand(
        kind: SendData,
        send_dst: @[bob.pk],
        send_val: "hello",
      ))

      skewTime(RELAY_MESSAGE_DURATION + 1)
      var bob2 = relay.authenticatedConn(bob.keys)
      check bob2.msgCount == 0
  
  test "max transfer":
    var relay = testRelay()
    let msgsize = RELAY_MAX_MESSAGE_SIZE div 2
    relay.max_transfer_rate = msgsize * 10
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    let count = relay.max_transfer_rate div msgsize + 2
    for i in 0..count:
      relay.handleCommand(alice, RelayCommand(
        kind: SendData,
        send_dst: @[bob.pk],
        send_val: "a".repeat(msgsize),
      ))
    let err = alice.pop(Error)
    check err.err_code == TransferLimitExceeeded
    check err.err_cmd == SendData
  
  test "invalid pubkey":
    var relay = testRelay()
    let msgsize = RELAY_MAX_MESSAGE_SIZE div 2
    relay.max_transfer_rate = msgsize * 10
    var alice = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_dst: @["invalid".SignPublicKey],
      send_val: "a",
    ))
    let err = alice.pop(Error)
    check err.err_code == InvalidParams
    check err.err_cmd == SendData

  test "overwrite key":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob1 = relay.authenticatedConn()
    relay.disconnect(bob1)

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "apple",
      send_dst: @[bob1.pk],
      send_val: "core",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "banana",
      send_dst: @[bob1.pk],
      send_val: "boat",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "apple",
      send_dst: @[bob1.pk],
      send_val: "pie",
    ))

    var bob2 = relay.authenticatedConn(bob1.keys)
    block:
      let data = bob2.pop(Data)
      check data.data_key == "banana"
      check data.data_src == alice.pk
      check data.data_val == "boat"
    block:
      let data = bob2.pop(Data)
      check data.data_key == "apple"
      check data.data_src == alice.pk
      check data.data_val == "pie"

  test "no overwrite empty key":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob1 = relay.authenticatedConn()
    relay.disconnect(bob1)

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "",
      send_dst: @[bob1.pk],
      send_val: "first",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "",
      send_dst: @[bob1.pk],
      send_val: "second",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "",
      send_dst: @[bob1.pk],
      send_val: "third",
    ))

    var bob2 = relay.authenticatedConn(bob1.keys)
    block:
      let data = bob2.pop(Data)
      check data.data_key == ""
      check data.data_src == alice.pk
      check data.data_val == "first"
    block:
      let data = bob2.pop(Data)
      check data.data_key == ""
      check data.data_src == alice.pk
      check data.data_val == "second"
    block:
      let data = bob2.pop(Data)
      check data.data_key == ""
      check data.data_src == alice.pk
      check data.data_val == "third"
  
  test "deliver once per pubkey":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    var carl = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "",
      send_dst: @[bob.pk, carl.pk],
      send_val: "hi",
    ))
    
    block:
      let data = bob.pop(Data)
      check data.data_key == ""
      check data.data_src == alice.pk
      check data.data_val == "hi"
    block:
      let data = carl.pop(Data)
      check data.data_key == ""
      check data.data_src == alice.pk
      check data.data_val == "hi"

  test "deliver to a, update val, deliver to a, b":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    var carl = relay.authenticatedConn()
    relay.disconnect(carl)

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "apple",
      send_dst: @[bob.pk, carl.pk],
      send_val: "core",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "apple",
      send_dst: @[bob.pk, carl.pk],
      send_val: "cider",
    ))
    var carl2 = relay.authenticatedConn(carl.keys)
    block:
      check bob.pop(Data).data_val == "core"
      check bob.pop(Data).data_val == "cider"
    block:
      check carl2.pop(Data).data_val == "cider" 
  
  test "drop recipient":
    # When updating a keyed message to a subset of recipients,
    # recipients not in the new send still get their old pending message
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    relay.disconnect(bob)
    var carl = relay.authenticatedConn()
    relay.disconnect(carl)

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "apple",
      send_dst: @[bob.pk, carl.pk],
      send_val: "core",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "apple",
      send_dst: @[bob.pk],  # Carl not included in update
      send_val: "cider",
    ))
    block:
      var bob2 = relay.authenticatedConn(bob.keys)
      check bob2.pop(Data).data_val == "cider"
    block:
      var carl2 = relay.authenticatedConn(carl.keys)
      # Carl still has his original pending message
      check carl2.pop(Data).data_val == "core"

  test "multiple senders same key":
    # Different senders can send messages with the same key to the same recipient
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    var carl = relay.authenticatedConn()
    relay.disconnect(carl)

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_key: "status",
      send_dst: @[carl.pk],
      send_val: "alice_v1",
    ))
    relay.handleCommand(bob, RelayCommand(
      kind: SendData,
      send_key: "status",
      send_dst: @[carl.pk],
      send_val: "bob_v1",
    ))

    var carl2 = relay.authenticatedConn(carl.keys)
    # Carl should receive both messages, one from alice and one from bob
    block:
      let msg1 = carl2.pop(Data)
      let msg2 = carl2.pop(Data)
      # Order might vary, so check both possibilities
      check (
        (msg1.data_src == alice.pk and msg1.data_val == "alice_v1" and
         msg2.data_src == bob.pk and msg2.data_val == "bob_v1") or
        (msg1.data_src == bob.pk and msg1.data_val == "bob_v1" and
         msg2.data_src == alice.pk and msg2.data_val == "alice_v1")
      ) 

suite "anon":

  test "PublishNote":
    let relay = testRelay()
    var alice = relay.anonConn()
    discard alice.pop(Who)
    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "foo",
      pub_data: "bar"
    ))
    let err = alice.pop(Error)
    check err.err_cmd == PublishNote
    check err.err_code == NotAllowed
  
  test "FetchNote":
    let relay = testRelay()
    var alice = relay.anonConn()
    discard alice.pop(Who)
    relay.handleCommand(alice, RelayCommand(
      kind: FetchNote,
      fetch_topic: "foo",
    ))
    let err = alice.pop(Error)
    check err.err_cmd == FetchNote
    check err.err_code == NotAllowed
  
  test "SendData":
    let relay = testRelay()
    var keys = genkeys()
    var alice = relay.anonConn()
    discard alice.pop(Who)
    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      send_dst: @[keys.pk],
      send_val: "bar",
    ))
    let err = alice.pop(Error)
    check err.err_cmd == SendData
    check err.err_code == NotAllowed

suite "stats":

  test "transfer basics":
    let db = open(":memory:", "", "", "")
    db.updateSchema()
    db.record_transfer_stat("ip1", "pubkey".SignPublicKey, data_in = 1000, data_out = 500)
    db.record_transfer_stat("ip1", "pubkey".SignPublicKey, data_in = 2000, data_out = 250)
    db.record_transfer_stat("ip2", "pubkey".SignPublicKey, data_in = 3000, data_out = 100)
    db.record_transfer_stat("ip1", "pubkey2".SignPublicKey, data_in = 500, data_out = 100)

    check db.stats_transfer_total(ip="ip1") == (1000+2000+500, 500+250+100, "ip1", "".SignPublicKey, "")
    check db.stats_transfer_total(pubkey="pubkey".SignPublicKey) == (1000+2000+3000, 500+250+100, "", "pubkey".SignPublicKey, "")
    check db.stats_transfer_total(pubkey="pubkey2".SignPublicKey) == (500, 100, "", "pubkey2".SignPublicKey, "")

  test "transfer timeperiods":
    let db = open(":memory:", "", "", "")
    db.updateSchema()
    db.record_transfer_stat_period("ip1", "pubkey".SignPublicKey, "2010-01", data_in = 1000, data_out = 500)
    db.record_transfer_stat_period("ip1", "pubkey".SignPublicKey, "2010-01", data_in = 2000, data_out = 250)
    db.record_transfer_stat_period("ip2", "pubkey".SignPublicKey, "2010-02", data_in = 3000, data_out = 100)
    db.record_transfer_stat_period("ip1", "pubkey2".SignPublicKey, "2010-02", data_in = 500, data_out = 100)

    check db.stats_transfer_total(period="2010-01") == (1000+2000, 500+250, "", "".SignPublicKey, "2010-01")
    check db.stats_transfer_total(period="2010-02") == (3000+500, 100+100, "", "".SignPublicKey, "2010-02")

suite "resp_id":

  test "Who message has resp_id 0":
    let relay = testRelay()
    let client = newTestClient(genkeys())
    var conn = relay.initAuth(client)
    let who = conn.pop(Who)
    check who.resp_id == 0

  test "Iam command response has matching resp_id":
    let relay = testRelay()
    let client = newTestClient(genkeys())
    var conn = relay.initAuth(client)
    let who = conn.pop(Who)
    let answer = who.who_challenge.answer(client.sk)

    relay.handleCommand(conn, RelayCommand(
      kind: Iam,
      resp_id: 42,
      iam_answer: answer,
      iam_pubkey: client.pk
    ))
    let ok = conn.pop(Okay)
    check ok.resp_id == 42

  test "PublishNote response has matching resp_id":
    let relay = testRelay()
    var alice = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      resp_id: 123,
      pub_topic: "test",
      pub_data: "data",
    ))
    let ok = alice.pop(Okay)
    check ok.resp_id == 123

  test "FetchNote response has matching resp_id":
    let relay = testRelay()
    var alice = relay.authenticatedConn()

    # Publish a note first
    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      pub_topic: "test",
      pub_data: "data",
    ))
    discard alice.pop(Okay)

    # Fetch the note with resp_id
    relay.handleCommand(alice, RelayCommand(
      kind: FetchNote,
      resp_id: 456,
      fetch_topic: "test",
    ))
    let note = alice.pop(Note)
    check note.resp_id == 456

  test "Error response has matching resp_id":
    let relay = testRelay()
    var alice = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      resp_id: 789,
      pub_topic: "a".repeat(RELAY_MAX_TOPIC_SIZE + 1),
      pub_data: "data",
    ))
    let err = alice.pop(Error)
    check err.resp_id == 789

  test "Data message has resp_id 0 (no command trigger)":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: SendData,
      resp_id: 111,
      send_dst: @[bob.pk],
      send_val: "hello",
    ))

    # Bob receives the Data message - it should have resp_id 0
    # because it wasn't triggered by Bob's command
    let data = bob.pop(Data)
    check data.resp_id == 0

  test "Multiple commands with different resp_ids":
    let relay = testRelay()
    var alice = relay.authenticatedConn()

    # Send multiple commands with different resp_ids
    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      resp_id: 100,
      pub_topic: "topic1",
      pub_data: "data1",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: PublishNote,
      resp_id: 200,
      pub_topic: "topic2",
      pub_data: "data2",
    ))

    let ok1 = alice.pop(Okay)
    check ok1.resp_id == 100
    let ok2 = alice.pop(Okay)
    check ok2.resp_id == 200

