# Copyright (c) One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

## These are the objects used for the protocol.
## This file should be kept free of dependencies other than the stdlib
## and should not include async stuff
## as it's meant to be referenced by outside libraries that may
## want to do things there own way.

import std/hashes
import std/options
import std/sequtils
import std/strformat
import std/strutils

type
  SignPublicKey* = distinct string
  SignSecretKey* = distinct string

  Challenge* = tuple
    bits: int
    rand: string
    opslimit: int
    memlimit: int
  
  ChallengeAnswer* = tuple
    nonce: int
    output: string
    signature: string

  MessageKind* = enum
    Who
    Okay
    Error
    Note
    Data
    Chunk
    ChunkStatus

  ErrorCode* = enum
    Generic = 0
    NotAllowed = 1
    TooLarge = 2
    StorageLimitExceeded = 3
    TransferLimitExceeeded = 4
    InvalidParams = 5
    NotFound = 6

  RelayMessage* = object
    resp_id*: int
    case kind*: MessageKind
    of Who:
      who_challenge*: Challenge
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
      data_src*: SignPublicKey
      data_val*: string
    of Chunk:
      chunk_src*: SignPublicKey
      chunk_key*: string
      chunk_val*: Option[string]
    of ChunkStatus:
      status_src*: SignPublicKey
      present*: seq[string]
      absent*: seq[string]

  CommandKind* = enum
    Iam
    PublishNote
    FetchNote
    SendData
    StoreChunk
    GetChunks
    HasChunks

  RelayCommand* = object
    resp_id*: int
    case kind*: CommandKind
    of Iam:
      iam_pubkey*: SignPublicKey
      iam_answer*: ChallengeAnswer
    of PublishNote:
      pub_topic*: string
      pub_data*: string
    of FetchNote:
      fetch_topic*: string
    of SendData:
      send_dst*: SignPublicKey
      send_val*: string
    of StoreChunk:
      chunk_dst*: seq[SignPublicKey]
      chunk_key*: string
      chunk_val*: string
    of GetChunks:
      chunk_src*: SignPublicKey
      chunk_keys*: seq[string]
    of HasChunks:
      has_src*: SignPublicKey
      has_keys*: seq[string]

const
  RELAY_MAX_TOPIC_SIZE* = 512
  RELAY_MAX_NOTE_SIZE* = 4096
  RELAY_MAX_NOTES* = 1000
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

proc nice*(k: SignPublicKey): string = nice(k.string)
proc `$`*(k: SignPublicKey): string = k.nice()
proc hash*(p: SignPublicKey): Hash {.borrow.}
proc `==`*(a,b: SignPublicKey): bool {.borrow.}

proc abbr*(a: SignPublicKey): string = abbr(a.nice)
proc abbr*(a: Option[SignPublicKey]): string =
  if a.isSome:
    a.get.abbr
  else:
    "none"

proc `$`*(ch: Challenge): string =
  result = &"({ch.bits} {ch.opslimit} {ch.memlimit} rand={ch.rand.nice})"

proc `$`*(ans: ChallengeAnswer): string =
  result = &"({ans.nonce} {ans.output} {ans.signature.nicelong})"

proc `$`*(msg: RelayMessage): string =
  result.add $msg.kind & "("
  case msg.kind
  of Who:
    result.add "challenge=" & $msg.who_challenge
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
  of ChunkStatus:
    result.add &"{msg.status_src.nice.abbr} present=["
    result.add msg.present.mapIt(it.nice.abbr).join(", ")
    result.add "] absent=["
    result.add msg.absent.mapIt(it.nice.abbr).join(", ")
    result.add "]"
  result.add ")"

proc `==`*(a, b: RelayMessage): bool =
  if a.kind != b.kind or a.resp_id != b.resp_id:
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
    of ChunkStatus:
      return a.status_src == b.status_src and a.present == b.present and a.absent == b.absent

proc `$`*(cmd: RelayCommand): string =
  result.add $cmd.kind & "("
  case cmd.kind
  of Iam:
    result.add &"{cmd.iam_pubkey.nice.abbr} {cmd.iam_answer}"
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
  of HasChunks:
    result.add &"{cmd.has_src.nice.abbr} keys=["
    result.add cmd.has_keys.mapIt(it.nice.abbr).join(", ")
    result.add "]"
  result.add ")"

proc `==`*(a, b: RelayCommand): bool =
  if a.kind != b.kind or a.resp_id != b.resp_id:
    return false
  else:
    case a.kind
    of Iam:
      return a.iam_pubkey == b.iam_pubkey and a.iam_answer == b.iam_answer
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
    of HasChunks:
      return a.has_src == b.has_src and a.has_keys == b.has_keys

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
  of ChunkStatus: 's'

proc deserialize*(kind: typedesc[MessageKind], val: char): MessageKind =
  case val
  of '?': Who
  of '+': Okay
  of '-': Error
  of 'n': Note
  of 'd': Data
  of 'k': Chunk
  of 's': ChunkStatus
  else: raise ValueError.newException("Unknown MessageKind: " & val)

proc serialize*(kind: CommandKind): char =
  case kind:
  of Iam: 'i'
  of PublishNote: 'p'
  of FetchNote: 'f'
  of SendData: 's'
  of StoreChunk: 'c'
  of GetChunks: 'g'
  of HasChunks: 't'

proc deserialize*(kind: typedesc[CommandKind], val: char): CommandKind =
  case val:
  of 'i': Iam
  of 'p': PublishNote
  of 'f': FetchNote
  of 's': SendData
  of 'c': StoreChunk
  of 'g': GetChunks
  of 't': HasChunks
  else: raise ValueError.newException("Unknown CommandKind: " & val)

proc serialize*(err: ErrorCode): char =
  chr(err.ord)

proc deserialize*(typ: typedesc[ErrorCode], ch: char): ErrorCode =
  try:
    ErrorCode(ord(ch))
  except:
    raise ValueError.newException("Unknown ErrorCode: " & ch)

proc serialize*(chal: Challenge): string =
  result.add nsencode($chal.bits)
  result.add nsencode(chal.rand)
  result.add nsencode($chal.opslimit)
  result.add nsencode($chal.memlimit)

proc deserialize*(typ: typedesc[Challenge], val: string): Challenge =
  var idx = 0
  let bits = val.nsdecode(idx).parseInt()
  let rand = val.nsdecode(idx)
  let opslimit = val.nsdecode(idx).parseInt()
  let memlimit = val.nsdecode(idx).parseInt()
  return (bits, rand, opslimit, memlimit)

proc serialize*(ans: ChallengeAnswer): string =
  result &= nsencode($ans.nonce)
  result &= nsencode(ans.output)
  result &= nsencode(ans.signature)

proc deserialize*(typ: typedesc[ChallengeAnswer], val: string): ChallengeAnswer =
  var idx = 0
  return (
    nonce: val.nsdecode(idx).parseInt(),
    output: val.nsdecode(idx),
    signature: val.nsdecode(idx),
  )

proc serialize*(keys: seq[SignPublicKey]): string =
  for key in keys:
    result &= nsencode(key.string)

proc deserializePubKeys*(val: string): seq[SignPublicKey] =
  var val = val
  while val.len > 0:
    result.add(val.nschop().SignPublicKey)

proc serialize*(s: seq[string]): string =
  for item in s:
    result &= nsencode(item)

proc deserialize*(typ: typedesc[seq[string]], val: string): seq[string] =
  var idx = 0
  while idx < val.len:
    result.add(val.nsdecode(idx))

proc serialize*(msg: RelayMessage): string =
  result &= msg.kind.serialize()
  # For Who and Data messages, resp_id is always omitted (always 0)
  if msg.kind notin {Who, Data}:
    result &= nsencode($msg.resp_id)
  case msg.kind
  of Who:
    result &= msg.who_challenge.serialize()
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
  of ChunkStatus:
    result &= msg.status_src.string.nsencode
    result &= nsencode(msg.present.serialize())
    result &= nsencode(msg.absent.serialize())


proc deserialize*(typ: typedesc[RelayMessage], s: string): RelayMessage =
  if s.len == 0:
    raise ValueError.newException("Empty RelayMessage")
  var idx = 0
  let kind = MessageKind.deserialize(s[idx])
  idx.inc()
  # For Who and Data messages, resp_id is always 0 and not serialized
  let resp_id = if kind in {Who, Data}:
      0
    else:
      s.nsdecode(idx).parseInt()
  case kind
  of Who:
    return RelayMessage(kind: Who, resp_id: resp_id, who_challenge: Challenge.deserialize(s[idx..^1]))
  of Okay:
    return RelayMessage(kind: Okay, resp_id: resp_id, ok_cmd: CommandKind.deserialize(s[idx]))
  of Error:
    return RelayMessage(
      kind: Error,
      resp_id: resp_id,
      err_cmd: CommandKind.deserialize(s[idx]),
      err_code: ErrorCode.deserialize(s[idx+1]),
      err_message: s[(idx+2)..^1]
    )
  of Note:
    return RelayMessage(
      kind: Note,
      resp_id: resp_id,
      note_topic: s.nsdecode(idx),
      note_data: s.nsdecode(idx),
    )
  of Data:
    return RelayMessage(
      kind: Data,
      resp_id: resp_id,
      data_src: s.nsdecode(idx).SignPublicKey,
      data_val: s.nsdecode(idx),
    )
  of Chunk:
    return RelayMessage(
      kind: Chunk,
      resp_id: resp_id,
      chunk_src: s.nsdecode(idx).SignPublicKey,
      chunk_key: s.nsdecode(idx),
      chunk_val: if idx >= s.len:
          none[string]()
        else:
          some(s.nsdecode(idx)),
    )
  of ChunkStatus:
    return RelayMessage(
      kind: ChunkStatus,
      resp_id: resp_id,
      status_src: s.nsdecode(idx).SignPublicKey,
      present: deserialize(seq[string], s.nsdecode(idx)),
      absent: deserialize(seq[string], s.nsdecode(idx)),
    )

proc serialize*(cmd: RelayCommand): string =
  result &= cmd.kind.serialize
  result &= nsencode($cmd.resp_id)
  case cmd.kind
  of Iam:
    result &= cmd.iam_pubkey.string.nsencode
    result &= cmd.iam_answer.serialize().nsencode
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
  of HasChunks:
    result &= cmd.has_src.string.nsencode
    result &= nsencode(cmd.has_keys.serialize())

proc deserialize*(typ: typedesc[RelayCommand], s: string): RelayCommand =
  if s.len == 0:
    raise ValueError.newException("Empty RelayCommand")
  var idx = 0
  let kind = CommandKind.deserialize(s[idx])
  idx.inc()
  let resp_id = s.nsdecode(idx).parseInt()
  case kind
  of Iam:
    return RelayCommand(
      kind: Iam,
      resp_id: resp_id,
      iam_pubkey: s.nsdecode(idx).SignPublicKey,
      iam_answer: ChallengeAnswer.deserialize(s.nsdecode(idx)),
    )
  of PublishNote:
    return RelayCommand(
      kind: PublishNote,
      resp_id: resp_id,
      pub_topic: s.nsdecode(idx),
      pub_data: s.nsdecode(idx),
    )
  of FetchNote:
    return RelayCommand(
      kind: FetchNote,
      resp_id: resp_id,
      fetch_topic: s.nsdecode(idx),
    )
  of SendData:
    return RelayCommand(
      kind: SendData,
      resp_id: resp_id,
      send_dst: s.nsdecode(idx).SignPublicKey,
      send_val: s.nsdecode(idx),
    )
  of StoreChunk:
    return RelayCommand(
      kind: StoreChunk,
      resp_id: resp_id,
      chunk_dst: deserializePubKeys(s.nsdecode(idx)),
      chunk_key: s.nsdecode(idx),
      chunk_val: s.nsdecode(idx),
    )
  of GetChunks:
    return RelayCommand(
      kind: GetChunks,
      resp_id: resp_id,
      chunk_src: s.nsdecode(idx).SignPublicKey,
      chunk_keys: deserialize(seq[string], s.nsdecode(idx)),
    )
  of HasChunks:
    return RelayCommand(
      kind: HasChunks,
      resp_id: resp_id,
      has_src: s.nsdecode(idx).SignPublicKey,
      has_keys: deserialize(seq[string], s.nsdecode(idx)),
    )
