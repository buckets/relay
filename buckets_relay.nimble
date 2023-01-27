# Package

version       = "0.1.0"
author        = "Matt Haggard"
description   = "The relay service for the Buckets budgeting app"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
installDirs   = @["partials", "static"]
bin           = @["brelay", "bclient"]


# Dependencies

requires "argparse == 2.0.1"
requires "libsodium == 0.6.0"
requires "mustache == 0.4.3"
requires "ndb == 0.19.9"
requires "nim >= 1.6.0"
requires "https://github.com/status-im/nim-websock.git#4c5e225eeb342a3b9cfb2fbdddd92d00568b5553"
requires "https://github.com/yglukhov/bearssl_pkey_decoder.git#546f8d9bb887ae1d8a23f62155c583acb0358046"
