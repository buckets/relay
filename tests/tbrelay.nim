import std/unittest
import std/logging
import ./util

import chronos

import brelay
import bclient

import relay/proto

proc tlog(msg: string) =
  debug "TEST: " & msg

test "copy":
  withinTmpDir:
    tlog "Adding users ..."
    addverifieduser("data.sqlite", "alice", "alice")
    addverifieduser("data.sqlite", "bob", "bob")
    let relayurl = "http://127.0.0.1:9001/relay"
    tlog "Starting relay ..."
    let server = startRelay("data.sqlite", 9001.Port, "127.0.0.1")
    tlog "Generating keys ..."
    let akeys = genkeys()
    let bkeys = genkeys()
    tlog "Sending from sender to receiver ..."
    let sendres = relaySend("hello", bkeys.pk,
      relayurl = relayurl,
      mykeys = akeys,
      username = "alice",
      password = "alice",
    )
    tlog "Receiving from sender ..."
    let recvres = relayReceive(akeys.pk,
      relayurl = relayurl,
      mykeys = bkeys,
      username = "bob",
      password = "bob",
    )
    tlog "Waiting for send to resolve"
    waitFor sendres
    tlog "Waiting for recv to resolve"
    let res = waitFor recvres
    check res == "hello"
