import std/macros

import libsodium/sodium
import libsodium/sodium_sizes

const
  singleusermode* = defined(relaysingleusermode)
  multiusermode* = not singleusermode

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