# Copyright (c) One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

## These are the objects used for the protocol.
## This file should be kept free of dependencies other than the stdlib
## as it's meant to be referenced by outside libraries.

import std/strformat
import std/base64
import std/hashes
import std/strutils

type
  PublicKey* = distinct string
  SecretKey* = distinct string

  MessageKind* = enum
    Who
    Okay
    Error
    Note
    Data

  ErrorCode* = enum
    Generic = 0
    TooLarge = 1

  RelayMessage* = object
    case kind*: MessageKind
    of Who:
      who_challenge*: string
    of Okay:
      ok_cmd*: CommandKind
    of Error:
      err_code*: ErrorCode
      err_message*: string
      err_cmd*: CommandKind
    of Note:
      note_topic*: string
      note_data*: string
    of Data:
      data_src*: PublicKey
      data_val*: string

  CommandKind* = enum
    Iam
    PublishNote
    FetchNote
    SendData

  RelayCommand* = object
    case kind*: CommandKind
    of Iam:
      iam_pubkey*: PublicKey
      iam_signature*: string
    of PublishNote:
      pub_topic*: string
      pub_data*: string
    of FetchNote:
      fetch_topic*: string
    of SendData:
      send_dst*: PublicKey
      send_val*: string

const
  RELAY_MAX_TOPIC_SIZE* = 512
  RELAY_MAX_NOTE_SIZE* = 4096
  RELAY_NOTE_DURATION* = 5 * 24 * 60 * 60
  RELAY_MAX_MESSAGE_SIZE* = 100_000
  RELAY_MESSAGE_DURATION* = 30 * 24 * 60 * 60
  RELAY_PUBKEY_MEMORY_SECONDS* = 60 * 24 * 60 * 60

template b64encode(x: string): string = base64.encode(x)

proc `$`*(k: PublicKey): string = b64encode(k.string)
proc hash*(p: PublicKey): Hash {.borrow.}
proc `==`*(a,b: PublicKey): bool {.borrow.}

proc abbr*(s: string, size = 6): string =
  if s.len > size:
    result.add s.substr(0, size) & "..."
  else:
    result.add(s)

proc abbr*(a: PublicKey): string = abbr($a)

proc `$`*(msg: RelayMessage): string =
  result.add $msg.kind & "("
  case msg.kind
  of Who:
    result.add "challenge=" & b64encode(msg.who_challenge).abbr
  of Okay:
    result.add &"cmd={msg.ok_cmd}"
  of Error:
    result.add &"cmd={msg.err_cmd} code={msg.err_code} msg={msg.err_message}"
  of Note:
    result.add &"'{msg.note_topic}' {msg.note_data.b64encode.abbr} ({msg.note_data.len})"
  of Data:
    result.add &"src={msg.data_src.abbr} data={msg.data_val.b64encode.abbr} ({msg.data_val.len})"
  result.add ")"

proc `==`*(a, b: RelayMessage): bool =
  if a.kind != b.kind:
    return false
  else:
    case a.kind
    of Who:
      return a.who_challenge == b.who_challenge
    of Okay:
      return a.ok_cmd == b.ok_cmd
    of Error:
      return a.err_cmd == b.err_cmd and a.err_code == b.err_code and a.err_message == b.err_message
    of Note:
      return a.note_data == b.note_data and a.note_topic == b.note_topic
    of Data:
      return a.data_src == b.data_src and a.data_val == b.data_val

proc `$`*(cmd: RelayCommand): string =
  result.add $cmd.kind & "("
  case cmd.kind
  of Iam:
    result.add &"{cmd.iam_pubkey.abbr} sig={cmd.iam_signature.b64encode.abbr}"
  of PublishNote:
    result.add &"'{cmd.pub_topic}' data={cmd.pub_data.b64encode}"
  of FetchNote:
    result.add &"'{cmd.fetch_topic}'"
  of SendData:
    result.add &"{cmd.send_dst.abbr} data={cmd.send_val.b64encode.abbr} ({cmd.send_val.len})"
  result.add ")"

proc `==`*(a, b: RelayCommand): bool =
  if a.kind != b.kind:
    return false
  else:
    case a.kind
    of Iam:
      return a.iam_pubkey == b.iam_pubkey and a.iam_signature == b.iam_signature
    of PublishNote:
      return a.pub_topic == b.pub_topic and a.pub_data == b.pub_data
    of FetchNote:
      return a.fetch_topic == b.fetch_topic
    of SendData:
      return a.send_dst == b.send_dst and a.send_val == b.send_val

#--------------------------------------------------------------
# serialization
#
# TODO: consider if this should belong in a different file
#--------------------------------------------------------------

proc nsencode*(x: string): string =
  ## Encode a string as a netstring
  $len(x) & ":" & x & ","

proc nsdecode*(x: string, start: var int = 0): string =
  ## Read the netstring from x starting at index `start`
  ## start will be moved to the next netstring location
  if x.len == 0:
    raise ValueError.newException("Empty string is invalid netstring")
  var cursor = start
  # get length prefix
  var expectedLength = 0
  block:
    var buf = ""
    while true:
      let ch = x[cursor]
      cursor.inc()
      case ch
      of '0'..'9':
        buf.add(ch)
      of ':':
        expectedLength = buf.parseInt()
        break
      else:
        raise ValueError.newException("Invalid length character: " & ch & " at position " & $cursor)
  
  # check for terminal and length
  let terminalIdx = cursor + expectedLength
  if terminalIdx >= x.len:
    raise ValueError.newException("Netstring incomplete")
  
  let terminalCh = x[terminalIdx]
  if terminalCh notin {',','\n'}:
    raise ValueError.newException("Invalid terminal character: " & terminalCh)
  
  result = x[cursor..(cursor + expectedLength - 1)]
  start = terminalIdx + 1


proc serialize*(kind: MessageKind): char =
  case kind
  of Who: '?'
  of Okay: '+'
  of Error: '-'
  of Note: 'n'
  of Data: 'd'

proc deserialize*(kind: typedesc[MessageKind], val: char): MessageKind =
  case val
  of '?': Who
  of '+': Okay
  of '-': Error
  of 'n': Note
  of 'd': Data
  else: raise ValueError.newException("Unknown MessageKind: " & val)

proc serialize*(kind: CommandKind): char =
  case kind:
  of Iam: 'i'
  of PublishNote: 'p'
  of FetchNote: 'f'
  of SendData: 's'

proc deserialize*(kind: typedesc[CommandKind], val: char): CommandKind =
  case val:
  of 'i': Iam
  of 'p': PublishNote
  of 'f': FetchNote
  of 's': SendData
  else: raise ValueError.newException("Unknown CommandKind: " & val)

proc serialize*(err: ErrorCode): char =
  case err
  of Generic: '0'
  of TooLarge: '1'

proc deserialize*(typ: typedesc[ErrorCode], ch: char): ErrorCode =
  case ch
  of '0': Generic
  of '1': TooLarge
  else: raise ValueError.newException("Unknown ErrorCode: " & ch)

proc serialize*(msg: RelayMessage): string =
  result &= msg.kind.serialize()
  case msg.kind
  of Who:
    result &= msg.who_challenge
  of Okay:
    result &= msg.ok_cmd.serialize()
  of Error:
    result &= msg.err_cmd.serialize()
    result &= msg.err_code.serialize()
    result &= msg.err_message
  of Note:
    result &= msg.note_topic.nsencode
    result &= msg.note_data.nsencode
  of Data:
    result &= msg.data_src.string.nsencode
    result &= msg.data_val.nsencode

proc deserialize*(typ: typedesc[RelayMessage], s: string): RelayMessage =
  if s.len == 0:
    raise ValueError.newException("Empty RelayMessage")
  let kind = MessageKind.deserialize(s[0])
  case kind
  of Who:
    return RelayMessage(kind: Who, who_challenge: s[1..^1])
  of Okay:
    return RelayMessage(kind: Okay, ok_cmd: CommandKind.deserialize(s[1]))
  of Error:
    return RelayMessage(
      kind: Error,
      err_cmd: CommandKind.deserialize(s[1]),
      err_code: ErrorCode.deserialize(s[2]),
      err_message: s[3..^1]
    )
  of Note:
    var idx = 1
    let note_topic = s.nsdecode(idx)
    let note_data = s.nsdecode(idx)
    return RelayMessage(
      kind: Note,
      note_topic: note_topic,
      note_data: note_data,
    )
  of Data:
    var idx = 1
    let data_src = s.nsdecode(idx).PublicKey
    let data_val = s.nsdecode(idx)
    return RelayMessage(
      kind: Data,
      data_src: data_src,
      data_val: data_val,
    )

proc serialize*(cmd: RelayCommand): string =
  result &= cmd.kind.serialize

proc deserialize*(typ: typedesc[RelayCommand], s: string): RelayCommand =
  if s.len == 0:
    raise ValueError.newException("Empty RelayCommand")
  let kind = CommandKind.deserialize(s[0])
  case kind
  of Iam: discard
  of PublishNote: discard
  of FetchNote: discard
  of SendData: discard
