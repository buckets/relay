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

proc pk(conn: var RelayConnection[TestClient]): PublicKey = conn.sender.pk
proc sk(conn: var RelayConnection[TestClient]): SecretKey = conn.sender.sk
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
    iam_answer: answer,
    iam_pubkey: client.pk
  ))
  let ok = conn.pop()
  doAssert ok.kind == Okay
  doAssert ok.ok_cmd == Iam
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
      send_dst: bob.pk,
      send_val: "hel\x00lo",
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
      send_dst: bob1.pk,
      send_val: "hel\x00lo",
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
      send_dst: alice.pk,
      send_val: "a".repeat(RELAY_MAX_MESSAGE_SIZE + 1),
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
        send_dst: bob.pk,
        send_val: "hello",
      ))

      skewTime(RELAY_MESSAGE_DURATION + 1)
      var bob2 = relay.authenticatedConn(bob.keys)
      check bob2.msgCount == 0
  
  test "max transfer":
    var relay = testRelay()
    let chunksize = RELAY_MAX_MESSAGE_SIZE div 2
    relay.max_transfer_rate = chunksize * 10
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    let count = relay.max_transfer_rate div chunksize + 2
    for i in 0..count:
      relay.handleCommand(alice, RelayCommand(
        kind: SendData,
        send_dst: bob.pk,
        send_val: "a".repeat(chunksize),
      ))
    let err = alice.pop(Error)
    check err.err_code == TransferLimitExceeeded
    check err.err_cmd == SendData


proc storeChunk(conn: var RelayConnection[TestClient], key: string, val: string, dst = newSeq[PublicKey]()) =
  conn.relay.handleCommand(conn, RelayCommand(
    kind: StoreChunk,
    chunk_dst: dst,
    chunk_key: key,
    chunk_val: val,
  ))

proc getChunk(conn: var RelayConnection[TestClient], src: var RelayConnection[TestClient], key: string): Option[string] =
  conn.relay.handleCommand(conn, RelayCommand(
    kind: GetChunks,
    chunk_src: src.pk,
    chunk_keys: @[key],
  ))
  let chunk = conn.pop(Chunk)
  return chunk.chunk_val

proc chunkExists(conn: var RelayConnection[TestClient], src: var RelayConnection[TestClient], key: string): bool =
  conn.relay.handleCommand(conn, RelayCommand(
    kind: ChunksPresent,
    present_src: src.pk,
    present_keys: @[key],
  ))
  let resp = conn.pop(ChunkStatus)
  return key in resp.present

suite "chunks":

  test "basic":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    relay.handleCommand(alice, RelayCommand(
      kind: StoreChunk,
      chunk_dst: @[bob.pk],
      chunk_key: "key1",
      chunk_val: "\x00data1",
    ))
    relay.handleCommand(alice, RelayCommand(
      kind: StoreChunk,
      chunk_dst: @[bob.pk],
      chunk_key: "key2",
      chunk_val: "data2",
    ))
    check bob.msgCount == 0
    
    relay.handleCommand(bob, RelayCommand(
      kind: GetChunks,
      chunk_src: alice.pk,
      chunk_keys: @["key1", "key2"],
    ))
    block:
      let chunk = bob.pop(Chunk)
      check chunk.chunk_src == alice.pk
      check chunk.chunk_key == "key1"
      check chunk.chunk_val.get() == "\x00data1"
    block:
      let chunk = bob.pop(Chunk)
      check chunk.chunk_src == alice.pk
      check chunk.chunk_key == "key2"
      check chunk.chunk_val.get() == "data2"
    
    relay.handleCommand(alice, RelayCommand(
      kind: GetChunks,
      chunk_src: alice.pk,
      chunk_keys: @["key2"],
    ))
    block:
      let chunk = alice.pop(Chunk)
      check chunk.chunk_src == alice.pk
      check chunk.chunk_key == "key2"
      check chunk.chunk_val.get() == "data2"
  
  test "overwrite":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    alice.storeChunk("key", "first")
    alice.storeChunk("key", "second")
    check alice.getChunk(alice, "key").get() == "second"
    check alice.chunkExists(alice, "key")

  test "multiple dst":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    var carl = relay.authenticatedConn()
    alice.storeChunk("key", "val", @[bob.pk, carl.pk])
    check bob.getChunk(alice, "key").get() == "val"
    check carl.getChunk(alice, "key").get() == "val"
  
  test "dne":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: GetChunks,
      chunk_src: alice.pk,
      chunk_keys: @["dne"],
    ))
    block:
      let chunk = alice.pop(Chunk)
      check chunk.chunk_src == alice.pk
      check chunk.chunk_key == "dne"
      check chunk.chunk_val.isNone()
    check alice.chunkExists(alice, "dne") == false
  
  test "only dst allowed":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    alice.storeChunk("key", "first")
    check bob.getChunk(alice, "key").isNone()
    check alice.chunkExists(alice, "key")
    check bob.chunkExists(alice, "key") == false

  when not defined(release):
    test "expiration":
      let relay = testRelay()
      var alice = relay.authenticatedConn()
      alice.storeChunk("key", "foo")
      check alice.chunkExists(alice, "key")
      skewTime(RELAY_MESSAGE_DURATION + 1)
      check alice.getChunk(alice, "key").isNone()
      check alice.chunkExists(alice, "key") == false
  
  when not defined(release):
    test "expiration update":
      let relay = testRelay()
      var alice = relay.authenticatedConn()
      alice.storeChunk("key", "foo")
      skewTime(RELAY_MESSAGE_DURATION - 1)
      alice.storeChunk("key", "foo")
      skewTime(3)
      check alice.getChunk(alice, "key").get() == "foo"
  
  when not defined(release):
    test "expiration update status":
      let relay = testRelay()
      var alice = relay.authenticatedConn()
      alice.storeChunk("key", "foo")
      checkpoint $relay.db.getAllRows(sql"SELECT src, key, last_used FROM chunk")
      skewTime(RELAY_MESSAGE_DURATION - 1)
      check alice.chunkExists(alice, "key")
      checkpoint $relay.db.getAllRows(sql"SELECT src, key, last_used FROM chunk")
      skewTime(3)
      checkpoint $relay.db.getAllRows(sql"SELECT src, key, last_used FROM chunk")
      check alice.chunkExists(alice, "key")
      

  test "remove dst":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()
    var sam = relay.authenticatedConn()
    alice.storeChunk("key", "first", @[bob.pk, sam.pk])
    check bob.getChunk(alice, "key").get() == "first"
    check bob.chunkExists(alice, "key")
    check sam.getChunk(alice, "key").get() == "first"
    check sam.chunkExists(alice, "key")
    alice.storeChunk("key", "first", @[bob.pk])
    check bob.getChunk(alice, "key").get() == "first"
    check bob.chunkExists(alice, "key")
    check sam.getChunk(alice, "key").isNone()
    check sam.chunkExists(alice, "key") == false

  test "max key len":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: StoreChunk,
      chunk_dst: @[],
      chunk_key: "a".repeat(RELAY_MAX_CHUNK_KEY_SIZE + 1),
      chunk_val: "data1",
    ))
    let err = alice.pop(Error)
    check err.err_cmd == StoreChunk
    check err.err_code == TooLarge

  test "max val len":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: StoreChunk,
      chunk_dst: @[],
      chunk_key: "a",
      chunk_val: "a".repeat(RELAY_MAX_CHUNK_SIZE + 1),
    ))
    let err = alice.pop(Error)
    check err.err_cmd == StoreChunk
    check err.err_code == TooLarge

  test "max key len get":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    relay.handleCommand(alice, RelayCommand(
      kind: GetChunks,
      chunk_src: alice.pk,
      chunk_keys: @["a".repeat(RELAY_MAX_CHUNK_KEY_SIZE + 1)],
    ))
    let err = alice.pop(Error)
    check err.err_cmd == GetChunks
    check err.err_code == TooLarge

  test "max dst.len":
    let relay = testRelay()
    var alice = relay.authenticatedConn()
    var dsts: seq[PublicKey]
    for i in 0..(RELAY_MAX_CHUNK_DSTS+1):
      dsts.add(genkeys().pk)
    relay.handleCommand(alice, RelayCommand(
      kind: StoreChunk,
      chunk_dst: dsts,
      chunk_key: "a",
      chunk_val: "b",
    ))
    let err = alice.pop(Error)
    check err.err_cmd == StoreChunk
    check err.err_code == TooLarge
  
  test "max storage":
    var relay = testRelay()
    relay.max_chunk_space = RELAY_MAX_CHUNK_SIZE * 3 - 1
    var alice = relay.authenticatedConn()
    var bob = relay.authenticatedConn()

    for i in 0..<3:
      relay.handleCommand(alice, RelayCommand(
        kind: StoreChunk,
        chunk_dst: @[bob.pk],
        chunk_key: "key1" & $i,
        chunk_val: "a".repeat(RELAY_MAX_CHUNK_SIZE),
      ))
    relay.handleCommand(alice, RelayCommand(
      kind: StoreChunk,
      chunk_dst: @[bob.pk],
      chunk_key: "lastkey",
      chunk_val: "a".repeat(RELAY_MAX_CHUNK_SIZE),
    ))
    let err = alice.pop(Error)
    check err.err_cmd == StoreChunk
    check err.err_code == StorageLimitExceeded


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
      send_dst: keys.pk,
      send_val: "bar",
    ))
    let err = alice.pop(Error)
    check err.err_cmd == SendData
    check err.err_code == NotAllowed
  
  test "StoreChunk":
    let relay = testRelay()
    var keys = genkeys()
    var alice = relay.anonConn()
    discard alice.pop(Who)
    relay.handleCommand(alice, RelayCommand(
      kind: StoreChunk,
      chunk_dst: @[keys.pk],
      chunk_key: "foo",
      chunk_val: "bar",
    ))
    let err = alice.pop(Error)
    check err.err_cmd == StoreChunk
    check err.err_code == NotAllowed

  test "GetChunks":
    let relay = testRelay()
    var keys = genkeys()
    var alice = relay.anonConn()
    discard alice.pop(Who)
    relay.handleCommand(alice, RelayCommand(
      kind: GetChunks,
      chunk_src: keys.pk,
      chunk_keys: @["foo"],
    ))
    let err = alice.pop(Error)
    check err.err_cmd == GetChunks
    check err.err_code == NotAllowed

suite "stats":

  test "transfer basics":
    let db = open(":memory:", "", "", "")
    db.updateSchema()
    db.record_transfer_stat("ip1", "pubkey".PublicKey, data_in = 1000, data_out = 500)
    db.record_transfer_stat("ip1", "pubkey".PublicKey, data_in = 2000, data_out = 250)
    db.record_transfer_stat("ip2", "pubkey".PublicKey, data_in = 3000, data_out = 100)
    db.record_transfer_stat("ip1", "pubkey2".PublicKey, data_in = 500, data_out = 100)

    check db.stats_transfer_total(ip="ip1") == (1000+2000+500, 500+250+100, "ip1", "".PublicKey, "")
    check db.stats_transfer_total(pubkey="pubkey".PublicKey) == (1000+2000+3000, 500+250+100, "", "pubkey".PublicKey, "")
    check db.stats_transfer_total(pubkey="pubkey2".PublicKey) == (500, 100, "", "pubkey2".PublicKey, "")

  test "transfer timeperiods":
    let db = open(":memory:", "", "", "")
    db.updateSchema()
    db.record_transfer_stat_period("ip1", "pubkey".PublicKey, "2010-01", data_in = 1000, data_out = 500)
    db.record_transfer_stat_period("ip1", "pubkey".PublicKey, "2010-01", data_in = 2000, data_out = 250)
    db.record_transfer_stat_period("ip2", "pubkey".PublicKey, "2010-02", data_in = 3000, data_out = 100)
    db.record_transfer_stat_period("ip1", "pubkey2".PublicKey, "2010-02", data_in = 500, data_out = 100)

    check db.stats_transfer_total(period="2010-01") == (1000+2000, 500+250, "", "".PublicKey, "2010-01")
    check db.stats_transfer_total(period="2010-02") == (3000+500, 100+100, "", "".PublicKey, "2010-02")

  