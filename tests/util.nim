import std/logging
import std/os; export os
import std/strformat

if os.getEnv("SHOW_LOGS") != "":
  var L = newConsoleLogger()
  addHandler(L)
else:
  echo "set SHOW_LOGS=something to see logs"
