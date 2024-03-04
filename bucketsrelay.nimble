# Package

version       = "0.3.1"
author        = "Matt Haggard"
description   = "The relay service for the Buckets budgeting app"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim", "mustache", "png"]


# Dependencies
requires "nim >= 1.6.0"
requires "argparse == 4.0.1"
requires "libsodium == 0.6.0"
requires "mustache == 0.4.3"
requires "ndb == 0.19.9"
requires "https://github.com/status-im/nim-stew.git#d085e48e89062de307aab0d0629fba2f867cb49a"
requires "https://github.com/status-im/nim-serialization.git#9f56a0738c616061382928b9f60e1c5721622f51"
requires "https://github.com/status-im/nim-json-serialization.git#b068e1440d4cb2cf3ede6b3567eaaeecd6c8c96a"
requires "https://github.com/status-im/nim-chronos.git#ba143e029f35fd9b4cd3d89d007cc834d0d5ba3c"
requires "https://github.com/cheatfate/nimcrypto.git#a065c1741836462762d18d2fced1fedd46095b02"
requires "https://github.com/status-im/nim-websock.git#fea05cde8b123b38d1a0a8524b77efbc84daa848"
requires "https://github.com/yglukhov/bearssl_pkey_decoder.git#546f8d9bb887ae1d8a23f62155c583acb0358046"


# dependency locks
requires "https://github.com/status-im/nim-zlib.git#826e2fc013f55b4478802d4f2e39f187c50d520a"

import std/os

task singleuserbins, "Build single user brelay and bclient bins":
  exec("mkdir -p bin")
  exec("nimble c -d:relaysingleusermode -o:bin/brelay src/brelay.nim")
  exec("nimble c -d:relaysingleusermode -o:bin/bclient src/bclient.nim")

task multiuserbins, "Build multi user brelay and bclient bins":
  exec("mkdir -p bin")
  exec("nimble c -o:bin/brelay src/brelay.nim")
  exec("nimble c -o:bin/bclient src/bclient.nim")
