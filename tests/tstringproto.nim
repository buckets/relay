# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import unittest
import strformat

import relay/proto
import relay/stringproto

proc cev(ev: RelayEvent) =
  doAssert ev == ev
  checkpoint "original: " & $ev
  let intermediate = ev.dumps()
  let actual = intermediate.loadsRelayEvent()
  checkpoint "actual:   " & $actual
  checkpoint "intermed: " & intermediate
  doAssert ev == actual, &"Expected {ev} to equal {actual}"

proc ccmd(cmd: RelayCommand) =
  doAssert cmd == cmd
  checkpoint "original: " & $cmd
  let intermediate = cmd.dumps()
  let actual = intermediate.loadsRelayCommand()
  checkpoint "actual:   " & $actual
  checkpoint "intermed: " & intermediate
  doAssert cmd == actual, &"Expected {cmd} to equal {actual}"

suite "RelayEvent":
  test "Who":
    cev RelayEvent(kind: Who, who_challenge: "something\x00!")
  test "Authenticated":
    cev RelayEvent(kind: Authenticated)
  test "Connected":
    cev RelayEvent(kind: Connected, conn_pubkey: "hi".PublicKey)
  test "Disconnected":
    cev RelayEvent(kind: Disconnected, dcon_pubkey: "hi".PublicKey)
  test "Data":
    cev RelayEvent(kind: Data, sender_pubkey: "hey".PublicKey, data: "bob")
  test "ErrorEvent":
    cev RelayEvent(kind: ErrorEvent, err_message: "foo")
  test "Entered":
    cev RelayEvent(kind: Entered, entered_pubkey: "alice".PublicKey)
  test "Exited":
    cev RelayEvent(kind: Exited, exited_pubkey: "bob".PublicKey)

suite "RelayCommand":

  test "Iam":
    ccmd RelayCommand(kind: Iam)
  test "Connect":
    ccmd RelayCommand(kind: Connect)
  test "Disconnect":
    ccmd RelayCommand(kind: Disconnect)
  test "SendData":
    ccmd RelayCommand(kind: SendData)