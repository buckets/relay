# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/logging
import std/strformat
import std/json

import chronos

import bucketsrelay/common
import bucketsrelay/server

proc monitorMemory() {.async.} =
  var
    lastTotal = 0
    lastOccupied = 0
    lastFree = 0
  while true:
    let
      newTotal = getTotalMem()
      newOccupied = getOccupiedMem()
      newFree = getFreeMem()
      diffTotal = newTotal - lastTotal
      diffOccupied = newOccupied - lastOccupied
      diffFree = newFree - lastFree
    debug "--- Memory report ---"
    debug &"Total memory:     {newTotal:>10} <- {lastTotal:>10} diff {diffTotal:>10}"
    debug &"Occupied memory:  {newOccupied:>10} <- {lastOccupied:>10} diff {diffOccupied:>10}"
    debug &"Free memory:      {newFree:>10} <- {lastFree:>10} diff {diffFree:>10}"
    lastTotal = newTotal
    lastOccupied = newOccupied
    lastFree = newFree
    await sleepAsync(10.seconds)

proc startRelaySingleUser*(port = 9001.Port, address = "127.0.0.1", username = "", password = ""): RelayServer {.singleuseronly.} =
  ## Start the relay server on the given port.
  result = newRelayServer(username, password)
  let taddress = initTAddress(address, port.int)
  info &"Starting Single-User Buckets Relay on {taddress} ..."
  stderr.flushFile
  result.start(taddress)

proc getRelayServer(dbfilename: string): RelayServer {.multiuseronly.} =
  newRelayServer(dbfilename, pubkey = AUTH_LICENSE_PUBKEY)

proc startRelay*(dbfilename: string, port = 9001.Port, address = "127.0.0.1"): RelayServer {.multiuseronly.} =
  ## Start the relay server on the given port.
  result = getRelayServer(dbfilename)
  let taddress = initTAddress(address, port.int)
  info &"Starting Buckets Relay on {taddress} ..."
  stderr.flushFile
  result.start(taddress)

proc addverifieduser*(dbfilename, username, password: string) {.multiuseronly.} =
  var rs = getRelayServer(dbfilename)
  let userid = rs.register_user(username, password)
  let token = rs.generate_email_verification_token(userid)
  doAssert rs.use_email_verification_token(userid, token) == true

proc blockuser*(dbfilename, email: string) {.multiuseronly.} =
  var rs = getRelayServer(dbfilename)
  let uid = rs.get_user_id(email)
  rs.block_user(uid)

proc unblockuser*(dbfilename, email: string) {.multiuseronly.} =
  var rs = getRelayServer(dbfilename)
  let uid = rs.get_user_id(email)
  rs.unblock_user(uid)

proc blocklicense*(dbfilename, email: string) {.multiuseronly.} =
  var rs = getRelayServer(dbfilename)
  let uid = rs.get_user_id(email)
  rs.disable_most_recently_used_license(uid)

proc stats(dbfilename: string, days = 30): JsonNode {.multiuseronly.} =
  result = %* {
    "days": days,
    "users": [],
    "ips": [],
  }
  var rs = newRelayServer(dbfilename, updateSchema = false, pubkey = AUTH_LICENSE_PUBKEY)
  for row in rs.top_data_users(20, days = days):
    result["users"].add(%* {
      "sent": row.data.sent,
      "recv": row.data.recv,
      "user": row.user,
    })
  for row in rs.top_data_ips(20, days = days):
    result["ips"].add(%* {
      "sent": row.data.sent,
      "recv": row.data.recv,
      "ip": row.ip,
    })

proc showStats(dbfilename: string, days = 30): string {.multiuseronly.} =
  ## Show some usage stats
  return stats(dbfilename, days).pretty

when defined(posix):
  proc getpass(prompt: cstring) : cstring {.header: "<unistd.h>", importc: "getpass".}
else:
  proc getpass(prompt: cstring): cstring =
    stdout.write(prompt)
    stdout.flushFile()
    stdin.readLine()
  
when isMainModule:
  import argparse
  newConsoleLogger(lvlAll, useStderr = true).addHandler()
  when multiusermode:
    var p = newParser:
      option("-d", "--database", help="User/stats database filename", default=some("bucketsrelay.sqlite"))
      command("adduser"):
        help("Add a user")
        arg("email", help="Email address of user")
        flag("--password-stdin", help="If given, read the password from stdin rather than from the terminal")
        run:
          var password = if opts.password_stdin:
              stdout.write("Password? ")
              stdout.flushFile
              stdin.readLine()
            else:
              $getpass("Password? ".cstring)
          addverifieduser(opts.parentOpts.database, opts.email, password)
          echo "added user ", opts.email
      command("blockuser"):
        help("Block a user from using the relay")
        arg("email", help="Email address of user to block")
        run:
          blockuser(opts.parentOpts.database, opts.email)
          echo "User blocked"
      command("unblockuser"):
        help("Unblock a previously blocked user")
        arg("email", help="Email address of user to block")
        run:
          unblockuser(opts.parentOpts.database, opts.email)
          echo "User unblocked"
      command("disablelicense"):
        help("Disable a user's most recently-used license")
        arg("email", help="Email address of user")
        run:
          blocklicense(opts.parentOpts.database, opts.email)
          echo "License disabled"
      command("stats"):
        help("Show some statistics")
        option("--days", help = "Show data for this number of days", default=some("30"))
        run:
          echo showStats(opts.parentOpts.database, days=opts.days.parseInt)
      command("server"):
        help("Start the relay server")
        option("-p", "--port", help="Port to run server on", default=some("9001"))
        option("-a", "--address", help="Address to run on", default=some("127.0.0.1"))
        run:
          var server = startRelay(opts.parentOpts.database, opts.port.parseInt.Port, opts.address)
          runForever()
  elif singleusermode:
    var p = newParser:
      command("server"):
        help("Start a single user relay server. Set RELAY_USERNAME and RELAY_PASSWORD environment variables")
        option("-p", "--port", help="Port to run server on", default=some("9001"))
        option("-a", "--address", help="Address to run on", default=some("127.0.0.1"))
        option("-u", "--username", help="Username", env = "RELAY_USERNAME")
        option("-p", "--password", help="Password", env = "RELAY_PASSWORD")
        run:
          var server = startRelaySingleUser(opts.username, opts.password, opts.port.parseInt.Port, opts.address)
          runForever()
  try:
    p.run()
  except UsageError:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)
