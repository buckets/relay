import std/unittest

import proto2

test "MessageKind":
  for kind in low(MessageKind)..high(MessageKind):
    check MessageKind.deserialize(kind.serialize()) == kind

test "CommandKind":
  for kind in low(CommandKind)..high(CommandKind):
    check CommandKind.deserialize(kind.serialize()) == kind

test "RelayMessage":
  for kind in low(MessageKind)..high(MessageKind):
    let example = case kind
      of Who: RelayMessage(kind: Who, who_challenge: "test")
      of Okay: RelayMessage(kind: Okay, ok_cmd: SendData)
      of Error: RelayMessage(kind: Error, err_cmd: SendData, err_code: TooLarge, err_message: "foo")
      of Note: RelayMessage(kind: Note, note_topic: "something", note_data: "data")
      of Data: RelayMessage(kind: Data, data_src: "hey".PublicKey, data_val: "foo")
    let serialized = example.serialize()
    checkpoint "serialized: " & serialized
    check RelayMessage.deserialize(serialized) == example

test "RelayCommand":
  for kind in low(CommandKind)..high(CommandKind):
    let example = case kind
      of Iam: RelayCommand(kind: Iam, iam_pubkey: "hey".PublicKey, iam_signature: "foo")
      of PublishNote: RelayCommand(kind: PublishNote, pub_topic: "topic", pub_data: "data")
      of FetchNote: RelayCommand(kind: FetchNote, fetch_topic: "topic")
      of SendData: RelayCommand(kind: SendData, dst: @["one".PublicKey, "two".PublicKey], data: "data")
    let serialized = example.serialize()
    checkpoint "serialized: " & serialized
    check RelayCommand.deserialize(serialized) == example