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
      of Who: RelayMessage(kind: Who, who_challenge: generateChallenge())
      of Okay: RelayMessage(kind: Okay, ok_cmd: SendData)
      of Error: RelayMessage(kind: Error, err_cmd: SendData, err_code: TooLarge, err_message: "foo")
      of Note: RelayMessage(kind: Note, note_topic: "something", note_data: "data")
      of Data: RelayMessage(kind: Data, data_src: "hey".PublicKey, data_val: "foo")
      of Chunk: RelayMessage(kind: Chunk, chunk_src: "hey".PublicKey, chunk_key: "key", chunk_val: some("theval"))
      of ChunkStatus: RelayMessage(kind: ChunkStatus, status_src: "a".PublicKey, present: @["foo"], absent: @["bar"])
    let serialized = example.serialize()
    info $example
    info "serialized: " & serialized.nice
    check RelayMessage.deserialize(serialized) == example

test "RelayCommand":
  for kind in low(CommandKind)..high(CommandKind):
    let example = case kind
      of Iam: RelayCommand(
        kind: Iam,
        iam_pubkey: "hey".PublicKey,
        iam_answer: (
          nonce: 1,
          output: "foo",
          signature: "hey",
        ),
      )
      of PublishNote: RelayCommand(kind: PublishNote, pub_topic: "topic", pub_data: "data")
      of FetchNote: RelayCommand(kind: FetchNote, fetch_topic: "topic")
      of SendData: RelayCommand(kind: SendData, send_dst: "one".PublicKey, send_val: "data")
      of StoreChunk: RelayCommand(
          kind: StoreChunk,
          chunk_dst: @["one".PublicKey],
          chunk_key: "theky",
          chunk_val: "someval"
        )
      of GetChunks: RelayCommand(kind: GetChunks, chunk_src: "hey".PublicKey, chunk_keys: @["foo", "bar"])
      of HasChunks: RelayCommand(
          kind: HasChunks,
          has_src: "hey".PublicKey,
          has_keys: @["foo", "Bar"],
        )
    let serialized = example.serialize()
    info $example
    info "serialized: " & serialized
    check RelayCommand.deserialize(serialized) == example

test "Chunk with none":
  let chunk = RelayMessage(kind: Chunk,
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
