# Package

version       = "0.1.0"
author        = "Matt Haggard"
description   = "The relay service for the Buckets budgeting app"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
bin           = @[
                  "buckets_relay",
                  "buckets_relay_cat",
                ]


# Dependencies

requires "nim >= 1.6.0"
requires "libsodium == 0.6.0"
requires "ndb == 0.19.9"
requires "protocols == 0.1.0"
#requires "ws == 0.5.0"
requires "argparse == 2.0.1"
