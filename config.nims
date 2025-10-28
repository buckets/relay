# See LICENSE.md for licensing
switch("gc", "orc")
switch("threads", "off")

import os
const ROOT = currentSourcePath.parentDir()
switch("dynlibOverride", "libsodium")

const archsegment = block:
  when hostCPU == "i386":
    "x32"
  elif hostCPU == "arm64":
    "arm64"
  else:
    "x64"

when defined(macosx):
  switch("passL", ROOT/"libs"/"libsodium"/"macos"/archsegment/"libsodium.a")
elif defined(linux):
  switch("cincludes", ROOT/"libs"/"libsodium"/"linux"/archsegment/"include")
  switch("clibdir", ROOT/"libs"/"libsodium"/"linux"/archsegment/"lib")
  switch("passL", "-lsodium")
elif defined(windows):
  switch("passL", ROOT/"libs"/"libsodium"/"win"/archsegment/"libsodium.a")