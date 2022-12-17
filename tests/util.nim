import std/logging
import std/os; export os
import std/random
import std/strformat

if os.getEnv("SHOW_LOGS") != "":
  var L = newConsoleLogger()
  addHandler(L)
else:
  echo "set SHOW_LOGS=something to see logs"

randomize()

proc tmpDir*(): string =
  result = os.getTempDir() / &"test{random.rand(10000000)}"
  result.createDir()

template withinTmpDir*(body:untyped):untyped =
  let
    tmp = tmpDir()
    olddir = getCurrentDir()
  setCurrentDir(tmp)
  body
  setCurrentDir(olddir)
  try:
    tmp.removeDir()
  except:
    echo "WARNING: failed to remove temporary test directory: ", getCurrentExceptionMsg()
