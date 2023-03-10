import std/unittest
import std/logging
import ./util

import chronos

import brelay
import bclient

import bucketsrelay/common
import bucketsrelay/proto

proc tlog(msg: string) =
  debug "TEST: " & msg

when multiusermode:
  test "copy":
    withinTmpDir:
      tlog "Adding users ..."
      addverifieduser("data.sqlite", "alice", "alice")
      addverifieduser("data.sqlite", "bob", "bob")
      let relayurl = "http://127.0.0.1:9001/v1/relay"
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

when singleusermode:
  test "copy":
    withinTmpDir:
      let relayurl = "http://127.0.0.1:9001/v1/relay"
      tlog "Starting relay ..."
      let server = startRelaySingleUser("alice", "password", 9001.Port, "127.0.0.1")
      tlog "Generating keys ..."
      let akeys = genkeys()
      let bkeys = genkeys()
      tlog "Sending from sender to receiver ..."
      let sendres = relaySend("hello", bkeys.pk,
        relayurl = relayurl,
        mykeys = akeys,
        username = "alice",
        password = "password",
      )
      tlog "Receiving from sender ..."
      let recvres = relayReceive(akeys.pk,
        relayurl = relayurl,
        mykeys = bkeys,
        username = "alice",
        password = "password",
      )
      tlog "Waiting for send to resolve"
      waitFor sendres
      tlog "Waiting for recv to resolve"
      let res = waitFor recvres
      check res == "hello"
