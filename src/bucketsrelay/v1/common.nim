import std/macros
import std/strformat
import std/random; export random

import chronicles

import libsodium/sodium
import libsodium/sodium_sizes

const
  singleusermode* = defined(relaysingleusermode)
  multiusermode* = not singleusermode
  relayverbose* = defined(relayverbose)

template nextDebugName*(): untyped =
  $rand(100000..999999)

template vlog*(x: varargs[string, `$`]): untyped =
  when relayverbose:
    debug x

proc hash_password*(password: string): string =
  # We use a lower memlimit because a stolen password is
  # easy to mitigate and doesn't cause immediate harm to users.
  let memlimit = max(crypto_pwhash_memlimit_min(), 10_000_000)
  crypto_pwhash_str(password, memlimit = memlimit)

proc verify_password*(pwhash: string, password: string): bool {.inline.} =
  crypto_pwhash_str_verify(pwhash, password)

macro multiuseronly*(fn: untyped): untyped =
  ## Add as a pragma to procs that are only available in multiusermode
  when multiusermode:
    fn
  else:
    newStmtList()

macro singleuseronly*(fn: untyped): untyped =
  ## Add as a pragma to procs that should only be available in singleusermode
  when singleusermode:
    fn
  else:
    newStmtList()

#------------------------------------------------------------
# Memory-checking helpers
#------------------------------------------------------------
var lastMem = getOccupiedMem()

proc checkmem*(name: string) =
  let newMem = getOccupiedMem()
  let diffMem = newMem - lastMem
  debug "checkmem", res = &"{diffMem:>10} = {newMem:>10} <- {lastMem:>10}  {name}"
  lastMem = newMem

template checkMemGrowth(name: string, body: untyped): untyped =
  let occ {.genSym.} = getOccupiedMem()
  body
  echo "Mem growth during: " & name & " " & $(getOccupiedMem() - occ)
