# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import strutils
import ./proto
import protocols/netstring

proc dumps*(ev: RelayEvent): string =
  ## Serialize a RelayEvent to a string. Opposite of loadsRelayEvent
  result = $ev.kind
  case ev.kind
  of Who:
    result.add nsencode(ev.who_challenge)
  of Authenticated:
    discard
  of Connected:
    result.add nsencode($ev.conn_id)
    result.add nsencode(ev.conn_pubkey.string)
  of Disconnected:
    result.add nsencode($ev.dcon_id)
    result.add nsencode(ev.dcon_pubkey.string)
  of Data:
    result.add nsencode($ev.sender_id)
    result.add nsencode(ev.data)
  of ErrorEvent:
    result.add nsencode(ev.err_message)

proc loadsRelayEvent*(msg: string): RelayEvent =
  ## Deserialize a RelayEvent from a string. Opposite of dumps
  let kind = case $msg[0]
    of $Who: Who
    of $Authenticated: Authenticated
    of $Connected: Connected
    of $Disconnected: Disconnected
    of $Data: Data
    of $ErrorEvent: ErrorEvent
    else:
      raise ValueError.newException("Unknown event type: " & msg[0])
  let rest = msg[1..^1]
  result = RelayEvent(kind: kind)
  var decoder = newNetstringDecoder()
  decoder.consume(rest)
  case kind
  of Who:
    result.who_challenge = decoder.nextMessage()
  of Authenticated:
    discard
  of Connected:
    result.conn_id = decoder.nextMessage().parseInt()
    result.conn_pubkey = decoder.nextMessage().PublicKey
  of Disconnected:
    result.dcon_id = decoder.nextMessage().parseInt()
    result.dcon_pubkey = decoder.nextMessage().PublicKey
  of Data:
    result.sender_id = decoder.nextMessage().parseInt()
    result.data = decoder.nextMessage()
  of ErrorEvent:
    result.err_message = decoder.nextMessage()

proc dumps*(cmd: RelayCommand): string =
  ## Serialize a RelayCommand to a string. Opposite of loadsRelayCommand.
  result = $cmd.kind
  case cmd.kind
  of Iam:
    result.add nsencode(cmd.iam_signature)
    result.add nsencode(cmd.iam_pubkey.string)
  of Connect:
    result.add nsencode(cmd.conn_pubkey.string)
  of Disconnect:
    result.add nsencode($cmd.dcon_id)
  of SendData:
    result.add nsencode($cmd.send_id)
    result.add nsencode(cmd.send_data)

proc loadsRelayCommand*(msg: string): RelayCommand =
  ## Deserialize a RelayCommand from a string. Opposite of dumps.
  let kind = case $msg[0]
    of $Iam: Iam
    of $Connect: Connect
    of $Disconnect: Disconnect
    of $SendData: SendData
    else:
      raise ValueError.newException("Unknown command type: " & msg[0])
  let rest = msg[1..^1]
  result = RelayCommand(kind: kind)
  var decoder = newNetstringDecoder()
  decoder.consume(rest)
  case kind
  of Iam:
    result.iam_signature = decoder.nextMessage()
    result.iam_pubkey = decoder.nextMessage().PublicKey
  of Connect:
    result.conn_pubkey = decoder.nextMessage().PublicKey
  of Disconnect:
    result.dcon_id = decoder.nextMessage().parseInt()
  of SendData:
    result.send_id = decoder.nextMessage().parseInt()
    result.send_data = decoder.nextMessage()
