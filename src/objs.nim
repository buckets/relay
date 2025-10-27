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

type
  PublicKey* = distinct string
  SecretKey* = distinct string

  MessageKind* = enum
    Who
    Okay
    Error
    Note
  
  CommandKind* = enum
    Iam
    PublishNote
    FetchNote

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

const
  MAX_TOPIC_SIZE* = 512
  MAX_NOTE_SIZE* = 8096
  RELAY_NOTE_DURATION* = 5 * 24 * 60 * 60

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
  result.add "(" & $msg.kind & " "
  case msg.kind
  of Who:
    result.add "challenge=" & b64encode(msg.who_challenge).abbr
  of Okay:
    result.add &"cmd={msg.ok_cmd}"
  of Error:
    result.add &"cmd={msg.err_cmd} code={msg.err_code} msg={msg.err_message}"
  of Note:
    result.add msg.note_data
  result.add ")"

proc `$`*(cmd: RelayCommand): string =
  result.add "(" & $cmd.kind & " "
  case cmd.kind
  of Iam:
    result.add &"{cmd.iam_pubkey.abbr} sig={cmd.iam_signature.b64encode.abbr}"
  of PublishNote:
    result.add &"'{cmd.pub_topic}' data={cmd.pub_data.b64encode}"
  of FetchNote:
    result.add &"'{cmd.fetch_topic}'"
  result.add ")"