# Copyright (c) One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

## These are the objects used for the protocol.
## This file should be kept free of dependencies other than the stdlib
## as it's meant to be referenced by outside libraries.

import std/hashes
import std/options
import std/sequtils
import std/strformat
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
    Chunk

  ErrorCode* = enum
    Generic = 0
    NotAllowed = 1
    TooLarge = 2

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
    of Chunk:
      chunk_src*: PublicKey
      chunk_key*: string
      chunk_val*: Option[string]

  CommandKind* = enum
    Iam
    PublishNote
    FetchNote
    SendData
    StoreChunk
    GetChunks

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
    of StoreChunk:
      chunk_dst*: seq[PublicKey]
      chunk_key*: string
      chunk_val*: string
    of GetChunks:
      chunk_src*: PublicKey
      chunk_keys*: seq[string]

const
  RELAY_MAX_TOPIC_SIZE* = 512
  RELAY_MAX_NOTE_SIZE* = 4096
  RELAY_NOTE_DURATION* = 5 * 24 * 60 * 60
  RELAY_MAX_MESSAGE_SIZE* = 4096
  RELAY_MAX_CHUNK_KEY_SIZE* = 4096
  RELAY_MAX_CHUNK_SIZE* = 65536
  RELAY_MAX_CHUNK_DSTS* = 32
  RELAY_MESSAGE_DURATION* = 30 * 24 * 60 * 60
  RELAY_PUBKEY_MEMORY_SECONDS* = 60 * 24 * 60 * 60

const
  nicestart = 'a' # '!'
  niceend = 'z' # '~'
  nicesize = ord(niceend) - ord(nicestart)

proc nice*(s: string): string =
  for c in s:
    case c
    of {'0'..'9', 'a'..'z', 'A'..'Z', ' '}: result.add c
    else:
      result.add chr(ord(c) mod nicesize + ord(nicestart))

proc abbr*(s: string, size = 6): string =
  if s.len > size:
    result.add s.substr(0, size) & "..."
  else:
    result.add(s)

proc nicelong*(s: string): string =
  result = $s.len & ":" & s.nice.abbr & ","

proc nicelong*(o: Option[string]): string =
  if o.isNone:
    result = "none"
  else:
    result = o.get().nicelong()

proc nice*(k: PublicKey): string = nice(k.string)
proc `$`*(k: PublicKey): string = k.nice()
proc hash*(p: PublicKey): Hash {.borrow.}
proc `==`*(a,b: PublicKey): bool {.borrow.}

proc abbr*(a: PublicKey): string = abbr(a.nice)

proc `$`*(msg: RelayMessage): string =
  result.add $msg.kind & "("
  case msg.kind
  of Who:
    result.add "challenge=" & msg.who_challenge.nicelong
  of Okay:
    result.add &"cmd={msg.ok_cmd}"
  of Error:
    result.add &"cmd={msg.err_cmd} code={msg.err_code} msg={msg.err_message.nice}"
  of Note:
    result.add &"'{msg.note_topic.nice}' val={msg.note_data.nicelong}"
  of Data:
    result.add &"{msg.data_src.nice.abbr} val={msg.data_val.nicelong}"
  of Chunk:
    result.add &"{msg.chunk_src.nice.abbr} {msg.chunk_key.nice.abbr}={msg.chunk_val.nicelong}"
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
    of Chunk:
      return a.chunk_src == b.chunk_src and a.chunk_key == b.chunk_key and a.chunk_val == b.chunk_val

proc `$`*(cmd: RelayCommand): string =
  result.add $cmd.kind & "("
  case cmd.kind
  of Iam:
    result.add &"{cmd.iam_pubkey.nice.abbr} sig={cmd.iam_signature.nicelong}"
  of PublishNote:
    result.add &"'{cmd.pub_topic.nice.abbr}' val={cmd.pub_data.nicelong}"
  of FetchNote:
    result.add &"'{cmd.fetch_topic.nice.abbr}'"
  of SendData:
    result.add &"{cmd.send_dst.nice.abbr} val={cmd.send_val.nicelong}"
  of StoreChunk:
    result.add &"{cmd.chunk_key.nice.abbr}={cmd.chunk_val.nicelong} dst=["
    result.add cmd.chunk_dst.mapIt(it.nice.abbr).join(", ")
    result.add "]"
  of GetChunks:
    result.add &"{cmd.chunk_src.nice.abbr} keys=["
    result.add cmd.chunk_keys.mapIt(it.nice.abbr).join(", ")
    result.add "]"
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
    of StoreChunk:
      return a.chunk_dst == b.chunk_dst and a.chunk_key == b.chunk_key and a.chunk_val == b.chunk_val
    of GetChunks:
      return a.chunk_src == b.chunk_src and a.chunk_keys == b.chunk_keys

#--------------------------------------------------------------
# serialization
#
# TODO: consider if this should belong in a different file
#--------------------------------------------------------------

const MAX_NETSTRING = 65536

type
  NetstringError* = object of CatchableError
  IncompleteNetstring* = object of NetstringError

proc nsencode*(x: string, terminal = ','): string =
  ## Encode a string as a netstring
  $len(x) & ":" & x & terminal

proc nsdecode*(x: string, start: var int, maxlen = MAX_NETSTRING): string =
  ## Read the netstring from x starting at index `start`
  ## start will be moved to the next netstring location
  if x.len == 0:
    raise IncompleteNetstring.newException("Empty string is invalid netstring")
  var cursor = start
  # 1. get length prefix
  var expectedLength = 0
  block:
    var buf = ""
    while true:
      let ch = try:
          x[cursor]
        except IndexDefect:
          raise IncompleteNetstring.newException("Not complete")
      cursor.inc()
      case ch
      of '0'..'9':
        buf.add(ch)
        if buf.parseInt > maxlen:
          raise NetstringError.newException("Exceeds max length")
      of ':':
        if buf.len == 0:
          raise NetstringError.newException("Missing starting length")
        if buf.len >= 2 and buf[0] == '0':
          raise NetstringError.newException("Invalid starting length")
        expectedLength = buf.parseInt()
        break
      else:
        raise NetstringError.newException("Invalid length character: " & ch & " at position " & $cursor)
  
  # 2. check for terminal and length
  let terminalIdx = cursor + expectedLength
  if terminalIdx >= x.len:
    raise IncompleteNetstring.newException("Netstring incomplete")
  
  let terminalCh = x[terminalIdx]
  if terminalCh notin {',','\n'}:
    raise NetstringError.newException("Invalid terminal character: " & terminalCh)
  
  # 3. get string
  result = x[cursor..(cursor + expectedLength - 1)]
  start = terminalIdx + 1

proc nsdecode*(x: string, maxlen = MAX_NETSTRING): string =
  var idx = 0
  return nsdecode(x, idx, maxlen = maxlen)

proc nschop*(x: var string, maxlen = MAX_NETSTRING): string =
  ## Get the first netstring from a string and return it.
  ## Also remove the first netstring from the passed-in string
  var idx = 0
  result = nsdecode(x, idx, maxlen = maxlen)
  x.delete(0..(idx-1))

proc serialize*(kind: MessageKind): char =
  case kind
  of Who: '?'
  of Okay: '+'
  of Error: '-'
  of Note: 'n'
  of Data: 'd'
  of Chunk: 'k'

proc deserialize*(kind: typedesc[MessageKind], val: char): MessageKind =
  case val
  of '?': Who
  of '+': Okay
  of '-': Error
  of 'n': Note
  of 'd': Data
  of 'k': Chunk
  else: raise ValueError.newException("Unknown MessageKind: " & val)

proc serialize*(kind: CommandKind): char =
  case kind:
  of Iam: 'i'
  of PublishNote: 'p'
  of FetchNote: 'f'
  of SendData: 's'
  of StoreChunk: 'c'
  of GetChunks: 'g'

proc deserialize*(kind: typedesc[CommandKind], val: char): CommandKind =
  case val:
  of 'i': Iam
  of 'p': PublishNote
  of 'f': FetchNote
  of 's': SendData
  of 'c': StoreChunk
  of 'g': GetChunks
  else: raise ValueError.newException("Unknown CommandKind: " & val)

proc serialize*(err: ErrorCode): char =
  case err
  of Generic: '0'
  of NotAllowed: '1'
  of TooLarge: '2'

proc deserialize*(typ: typedesc[ErrorCode], ch: char): ErrorCode =
  case ch
  of '0': Generic
  of '1': NotAllowed
  of '2': TooLarge
  else: raise ValueError.newException("Unknown ErrorCode: " & ch)

proc serialize*(keys: seq[PublicKey]): string =
  for key in keys:
    result &= nsencode(key.string)

proc deserializePubKeys*(val: string): seq[PublicKey] =
  var val = val
  while val.len > 0:
    result.add(val.nschop().PublicKey)

proc serialize*(s: seq[string]): string =
  for item in s:
    result &= nsencode(item)

proc deserialize*(typ: typedesc[seq[string]], val: string): seq[string] =
  var idx = 0
  while idx < val.len:
    result.add(val.nsdecode(idx))

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
  of Chunk:
    result &= msg.chunk_src.string.nsencode
    result &= msg.chunk_key.nsencode
    if msg.chunk_val.isSome:
      result &= msg.chunk_val.get().nsencode


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
  of Chunk:
    var idx = 1
    let chunk_src = s.nsdecode(idx).PublicKey
    let chunk_key = s.nsdecode(idx)
    let chunk_val = if idx >= s.len:
        none[string]()
      else:
        some(s.nsdecode(idx))
    return RelayMessage(
      kind: Chunk,
      chunk_src: chunk_src,
      chunk_key: chunk_key,
      chunk_val: chunk_val,
    )

proc serialize*(cmd: RelayCommand): string =
  result &= cmd.kind.serialize
  case cmd.kind
  of Iam:
    result &= cmd.iam_pubkey.string.nsencode
    result &= cmd.iam_signature.nsencode
  of PublishNote:
    result &= cmd.pub_topic.nsencode
    result &= cmd.pub_data.nsencode
  of FetchNote:
    result &= cmd.fetch_topic.nsencode
  of SendData:
    result &= cmd.send_dst.string.nsencode
    result &= cmd.send_val.nsencode
  of StoreChunk:
    result &= nsencode(cmd.chunk_dst.serialize())
    result &= cmd.chunk_key.nsencode
    result &= cmd.chunk_val.nsencode
  of GetChunks:
    result &= cmd.chunk_src.string.nsencode
    result &= nsencode(cmd.chunk_keys.serialize())

proc deserialize*(typ: typedesc[RelayCommand], s: string): RelayCommand =
  if s.len == 0:
    raise ValueError.newException("Empty RelayCommand")
  let kind = CommandKind.deserialize(s[0])
  case kind
  of Iam:
    var idx = 1
    return RelayCommand(
      kind: Iam,
      iam_pubkey: s.nsdecode(idx).PublicKey,
      iam_signature: s.nsdecode(idx),
    )
  of PublishNote:
    var idx = 1
    return RelayCommand(
      kind: PublishNote,
      pub_topic: s.nsdecode(idx),
      pub_data: s.nsdecode(idx),
    )
  of FetchNote:
    var idx = 1
    return RelayCommand(
      kind: FetchNote,
      fetch_topic: s.nsdecode(idx),
    )
  of SendData:
    var idx = 1
    return RelayCommand(
      kind: SendData,
      send_dst: s.nsdecode(idx).PublicKey,
      send_val: s.nsdecode(idx),
    )
  of StoreChunk:
    var idx = 1
    return RelayCommand(
      kind: StoreChunk,
      chunk_dst: deserializePubKeys(s.nsdecode(idx)),
      chunk_key: s.nsdecode(idx),
      chunk_val: s.nsdecode(idx),
    )
  of GetChunks:
    var idx = 1
    return RelayCommand(
      kind: GetChunks,
      chunk_src: s.nsdecode(idx).PublicKey,
      chunk_keys: deserialize(seq[string], s.nsdecode(idx)),
    )
