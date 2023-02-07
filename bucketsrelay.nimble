# Package

version       = "0.2.0"
author        = "Matt Haggard"
description   = "The relay service for the Buckets budgeting app"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim", "mustache", "png"]
bin           = @["brelay", "bclient"]


# Dependencies

requires "argparse == 4.0.1"
requires "libsodium == 0.6.0"
requires "mustache == 0.4.3"
requires "ndb == 0.19.9"
requires "nim >= 1.6.0"
requires "https://github.com/status-im/nim-websock.git#fea05cde8b123b38d1a0a8524b77efbc84daa848"
requires "https://github.com/yglukhov/bearssl_pkey_decoder.git#546f8d9bb887ae1d8a23f62155c583acb0358046"

# dependency locks
requires "https://github.com/status-im/nim-zlib.git#826e2fc013f55b4478802d4f2e39f187c50d520a"
