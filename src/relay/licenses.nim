import std/json
import std/strformat
import std/strutils
import std/times

import ./jwtrsaonly

proc formatForEmail*(x: string): string =
  ## Format a base64-encoded string nicely for email delivery
  for i,c in x:
    result.add(c)
    if (i+1) mod 40 == 0:
      result.add "\n"
    elif (i+1) mod 10 == 0:
      result.add " "
  if result[^1] != '\n':
    result.add "\n"

#------------------------------------------------------
# V1 RSA License
#------------------------------------------------------
const
  rsaPrefix = "-----BEGIN RSA PRIVATE KEY-----"
  rsaSuffix = "-----END RSA PRIVATE KEY-----"
  licensePrefix = "------------- START LICENSE ---------------"
  licenseSuffix = "------------- END LICENSE -----------------"

type
  BucketsV1License* = distinct string

proc unformatLicense*(x: string): BucketsV1License =
  var tmp = x.replace(licensePrefix, "").replace(licenseSuffix, "")
  var res: string
  for c in tmp:
    case c
    of 'a'..'z','A'..'Z','0'..'9','+','=','_','-','/','.':
      res.add c
    else:
      discard
  return res.BucketsV1License
  
proc createV1License*(privateKey: string, email: string): BucketsV1License =
  ## Generate a new license
  var privateKey = privateKey.replace(rsaPrefix, "")
  privateKey = privateKey.replace(rsaSuffix, "")
  privateKey = privateKey.strip().replace(" ", "\n")
  privateKey = &"{rsaPrefix}\n{privateKey}\n{rsaSuffix}"
  var token = toJWT( %* {
    "header": {
      "alg": "RS256",
      "typ": "JWT"
    },
    "claims": {
      "email": email,
      "iat": getTime().toUnix(),
    }
  })
  token.sign(privateKey)
  return ($token).BucketsV1License

proc `$`*(license: BucketsV1License): string =
  ## Format a license for delivery in email
  result.add licensePrefix & "\n"
  result.add license.string.formatForEmail()
  result.add licenseSuffix

proc verify*(license: BucketsV1License, pubkey: string): bool =
  ## Return true if the license is valid, raise an exception if not
  result = false
  let jwtToken = license.string.toJWT()
  result = jwtToken.verify(pubkey)

proc extractEmail*(license: BucketsV1License): string =
  ## Extract the email address this license was issued to
  try:
    let jwt = license.string.toJWT()
    return $jwt.claims["email"].getStr()
  except:
    discard

