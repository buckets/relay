import std/deques
import std/logging
import std/unittest
import std/os

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

proc pk(conn: var RelayConnection[TestClient]): PublicKey = conn.sender.pk
proc sk(conn: var RelayConnection[TestClient]): SecretKey = conn.sender.sk

proc authenticatedConn(relay: Relay): RelayConnection[TestClient] =
  let client = newTestClient(genkeys())
  var conn = relay.initAuth(client)
  let who = conn.pop()
  doAssert who.kind == Who
  let sig = client.sk.sign(who.who_challenge)
  relay.handleCommand(conn, RelayCommand(kind: Iam, iam_signature: sig, iam_pubkey: client.pk))
  let ok = conn.pop()
  doAssert ok.kind == Okay
  doAssert ok.ok_cmd == Iam
  return conn

#---------------------------------
# End of TestClient
#---------------------------------

test "auth":
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

test "PublishNote":
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

test "fetch prior to pub":
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

test "iam twice": check false
test "iam invalid sig": check false
test "publish max size topic": check false
test "publish max size data": check false
test "publish expiration": check false
test "fetch dne topic": check false
test "fetch note again": check false
test "limit number of simultaneous fetches": check false
test "sub then disconnect, the pub": check false
