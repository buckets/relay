import std/unittest
import std/logging
import std/options

import ./util
import bucketsrelay/v2/proto2
import bucketsrelay/v2/objs

test "MessageKind":
  for kind in low(MessageKind)..high(MessageKind):
    check MessageKind.deserialize(kind.serialize()) == kind

test "CommandKind":
  for kind in low(CommandKind)..high(CommandKind):
    check CommandKind.deserialize(kind.serialize()) == kind

test "RelayMessage":
  for kind in low(MessageKind)..high(MessageKind):
    let example = case kind
      of Who: RelayMessage(kind: Who, resp_id: 0, who_challenge: generateChallenge())
      of Okay: RelayMessage(kind: Okay, resp_id: 42, ok_cmd: SendData)
      of Error: RelayMessage(kind: Error, resp_id: 123, err_cmd: SendData, err_code: TooLarge, err_message: "foo")
      of Note: RelayMessage(kind: Note, resp_id: 456, note_topic: "something", note_data: "data")
      of Data: RelayMessage(kind: Data, resp_id: 0, data_src: "hey".PublicKey, data_val: "foo")
      of Chunk: RelayMessage(kind: Chunk, resp_id: 789, chunk_src: "hey".PublicKey, chunk_key: "key", chunk_val: some("theval"))
      of ChunkStatus: RelayMessage(kind: ChunkStatus, resp_id: 999, status_src: "a".PublicKey, present: @["foo"], absent: @["bar"])
    let serialized = example.serialize()
    info $example
    info "serialized: " & serialized.nice
    check RelayMessage.deserialize(serialized) == example

test "RelayCommand":
  for kind in low(CommandKind)..high(CommandKind):
    let example = case kind
      of Iam: RelayCommand(
        kind: Iam,
        resp_id: 1,
        iam_pubkey: "hey".PublicKey,
        iam_answer: (
          nonce: 1,
          output: "foo",
          signature: "hey",
        ),
      )
      of PublishNote: RelayCommand(kind: PublishNote, resp_id: 100, pub_topic: "topic", pub_data: "data")
      of FetchNote: RelayCommand(kind: FetchNote, resp_id: 200, fetch_topic: "topic")
      of SendData: RelayCommand(kind: SendData, resp_id: 300, send_dst: "one".PublicKey, send_val: "data")
      of StoreChunk: RelayCommand(
          kind: StoreChunk,
          resp_id: 400,
          chunk_dst: @["one".PublicKey],
          chunk_key: "theky",
          chunk_val: "someval"
        )
      of GetChunks: RelayCommand(kind: GetChunks, resp_id: 500, chunk_src: "hey".PublicKey, chunk_keys: @["foo", "bar"])
      of HasChunks: RelayCommand(
          kind: HasChunks,
          resp_id: 600,
          has_src: "hey".PublicKey,
          has_keys: @["foo", "Bar"],
        )
    let serialized = example.serialize()
    info $example
    info "serialized: " & serialized
    check RelayCommand.deserialize(serialized) == example

test "Chunk with none":
  let chunk = RelayMessage(kind: Chunk,
    resp_id: 888,
    chunk_src: "foo".PublicKey,
    chunk_key: "key",
    chunk_val: none[string](),
  )
  info $chunk
  let serialized = chunk.serialize()
  info "serialized: " & serialized
  check RelayMessage.deserialize(serialized) == chunk

test "ErrorCodes":
  for err in low(ErrorCode)..high(ErrorCode):
    let serialized = err.serialize()
    checkpoint "serialized.nice: " & nice($serialized)
    check ErrorCode.deserialize(serialized) == err

test "resp_id serialization":
  # Test that resp_id values are preserved during serialization
  let msg1 = RelayMessage(kind: Okay, resp_id: 12345, ok_cmd: SendData)
  check RelayMessage.deserialize(msg1.serialize()).resp_id == 12345

  let msg2 = RelayMessage(kind: Error, resp_id: 99999, err_cmd: Iam, err_code: Generic, err_message: "test")
  check RelayMessage.deserialize(msg2.serialize()).resp_id == 99999

  let msg3 = RelayMessage(kind: Who, resp_id: 0, who_challenge: generateChallenge())
  check RelayMessage.deserialize(msg3.serialize()).resp_id == 0

  let cmd1 = RelayCommand(kind: PublishNote, resp_id: 54321, pub_topic: "topic", pub_data: "data")
  check RelayCommand.deserialize(cmd1.serialize()).resp_id == 54321

  let cmd2 = RelayCommand(kind: SendData, resp_id: 0, send_dst: "dst".PublicKey, send_val: "val")
  check RelayCommand.deserialize(cmd2.serialize()).resp_id == 0
