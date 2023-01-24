switch("gc", "orc")

when defined(linux):
  import os
  switch("dynlibOverride", "libsodium")
  switch("cincludes", "/usr/include")
  switch("clibdir", "/usr/lib")
  switch("passL", "-lsodium")
