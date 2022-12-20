# Package

version       = "0.1.0"
author        = "Matt Haggard"
description   = "The relay service for the Buckets budgeting app"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
installDirs   = @["src/partials", "src/static"]
bin           = @["brelay", "bclient"]


# Dependencies

requires "argparse == 2.0.1"
requires "libsodium == 0.6.0"
requires "mustache == 0.4.3"
requires "ndb == 0.19.9"
requires "nim >= 1.6.0"
requires "websock == 0.1.0"