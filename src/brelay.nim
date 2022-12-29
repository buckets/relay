# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/logging
import std/strformat
import std/json

import chronos

import relay/server

proc startRelay*(dbfilename: string, port = 9001.Port, address = "127.0.0.1"): RelayServer =
  ## Start the relay server on the given port.
  result = newRelayServer(dbfilename)
  let taddress = initTAddress(address, port.int)
  info &"Starting Buckets Relay on {taddress} ..."
  stderr.flushFile
  result.start(taddress)

proc addverifieduser*(dbfilename, username, password: string) =
  var rs = newRelayServer(dbfilename)
  let userid = rs.register_user(username, password)
  let token = rs.generate_email_verification_token(userid)
  doAssert rs.use_email_verification_token(userid, token) == true

proc stats(dbfilename: string, days = 30): JsonNode =
  result = %* {
    "days": days,
    "users": [],
    "ips": [],
  }
  var rs = newRelayServer(dbfilename, updateSchema = false)
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

proc showStats(dbfilename: string, days = 30): string =
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
  var p = newParser:
    option("-d", "--database", help="User/stats database filename", default=some("buckets_relay.sqlite"))
    command("adduser"):
      help("Add a user")
      arg("username", help="Email address/username of user")
      flag("--password-stdin", help="If given, read the password from stdin rather than from the terminal")
      run:
        let username = opts.username
        var password = if opts.password_stdin:
            stdout.write("Password? ")
            stdout.flushFile
            stdin.readLine()
          else:
            $getpass("Password? ".cstring)
        addverifieduser(opts.parentOpts.database, username, password)
        echo "added user ", username
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
  try:
    p.run()
  except UsageError:
    stderr.writeLine getCurrentExceptionMsg()
    quit(1)
