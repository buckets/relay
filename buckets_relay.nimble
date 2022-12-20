# Package

version       = "0.1.0"
author        = "Matt Haggard"
description   = "The relay service for the Buckets budgeting app"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
bin           = @[
                  "brelay",
                  "bclient",
                ]


# Dependencies

requires "nim >= 1.6.0"
requires "libsodium == 0.6.0"
requires "ndb == 0.19.9"
requires "argparse == 2.0.1"
requires "websock == 0.1.0"