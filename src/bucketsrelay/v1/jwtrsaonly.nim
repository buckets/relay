# This code comes from https://github.com/yglukhov/nim-jwt
# but with modifications to work with the version of BearSSL
# included with this project and only support RSA256 JWTs.

# The MIT License (MIT)

# Copyright (c) 2017 Yuriy Glukhov

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import std/base64
import std/json
import std/strutils

import bearssl
import bearssl_pkey_decoder

#--------------------------------------
# jwt/private/utils
#--------------------------------------

proc encodeUrlSafe(s: openarray[byte]): string =
  when NimMajor >= 1 and (NimMinor >= 1 or NimPatch >= 2):
    result = base64.encode(s)
  else:
    result = base64.encode(s, newLine="")
  while result.endsWith("="):
    result.setLen(result.len - 1)
  result = result.replace('+', '-').replace('/', '_')

proc encodeUrlSafe(s: openarray[char]): string {.inline.} =
  encodeUrlSafe(s.toOpenArrayByte(s.low, s.high))

proc decodeUrlSafeAsString(s: string): string =
  var s = s.replace('-', '+').replace('_', '/')
  while s.len mod 4 > 0:
    s &= "="
  base64.decode(s)

proc decodeUrlSafe(s: string): seq[byte] =
  cast[seq[byte]](decodeUrlSafeAsString(s))

#--------------------------------------
# jwt/private/jose
#--------------------------------------

proc toBase64(j: JsonNode): string =
  encodeUrlSafe($j)

#--------------------------------------
# jwt/crypto
#--------------------------------------

# This pragma should be the same as in nim-bearssl/decls.nim
{.pragma: bearSslFunc, cdecl, gcsafe, noSideEffect, raises: [].}

#--------------------------------------
# Custom PEM-decoding
#--------------------------------------

proc invalidPemKey() =
  raise newException(ValueError, "Invalid PEM encoding")

proc pemDecoderLoop(pem: string, prc: proc(ctx: pointer, pbytes: pointer, nbytes: uint) {.bearSslFunc.}, ctx: pointer) =
  var pemCtx: PemDecoderContext
  pemDecoderInit(pemCtx)
  var length = len(pem)
  var offset = 0
  var inobj = false
  while length > 0:
    var tlen = pemDecoderPush(pemCtx,
                              unsafeAddr pem[offset], length.uint).int
    offset = offset + tlen
    length = length - tlen

    let event = pemDecoderEvent(pemCtx)
    if event == PEM_BEGIN_OBJ:
      inobj = true
      pemDecoderSetdest(pemCtx, prc, ctx)
    elif event == PEM_END_OBJ:
      if inobj:
        inobj = false
      else:
        break
    elif event == 0 and length == 0:
      break
    else:
      invalidPemKey()

proc decodeFromPem(skCtx: var SkeyDecoderContext, pem: string) =
  skeyDecoderInit(skCtx)
  pemDecoderLoop(pem, cast[proc(ctx: pointer, pbytes: pointer, nbytes: uint) {.bearSslFunc.}](skeyDecoderPush), addr skCtx)
  if skeyDecoderLastError(skCtx) != 0: invalidPemKey()

proc decodeFromPem(pkCtx: var PkeyDecoderContext, pem: string) =
  pkeyDecoderInit(addr pkCtx)
  pemDecoderLoop(pem, cast[proc(ctx: pointer, pbytes: pointer, nbytes: uint) {.bearSslFunc.}](pkeyDecoderPush), addr pkCtx)
  if pkeyDecoderLastError(addr pkCtx) != 0: invalidPemKey()

proc calcHash(alg: ptr HashClass, data: string, output: var array[64, byte]) =
  var ctx: array[512, byte]
  let pCtx = cast[ptr ptr HashClass](addr ctx[0])
  assert(alg.contextSize <= sizeof(ctx).uint)
  alg.init(pCtx)
  if data.len > 0:
    alg.update(pCtx, unsafeAddr data[0], data.len.uint)
  alg.`out`(pCtx, addr output[0])

proc bearSignRSPem(data, key: string, alg: ptr HashClass, hashOid: cstring, hashLen: int): seq[byte] =
  # Step 1. Extract RSA key from `key` in PEM format
  var skCtx: SkeyDecoderContext
  decodeFromPem(skCtx, key)
  if skeyDecoderKeyType(skCtx) != KEYTYPE_RSA:
    invalidPemKey()

  template privateKey(): RsaPrivateKey = skCtx.key.rsa

  # Step 2. Hash!
  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let sigLen = (privateKey.nBitlen + 7) div 8
  result = newSeqUninitialized[byte](sigLen)
  let s = rsaPkcs1SignGetDefault()
  assert(not s.isNil)
  if s(cast[ptr byte](hashOid), addr digest[0], hashLen.uint, addr privateKey, addr result[0]) != 1:
    raise newException(ValueError, "Could not sign")

proc bearVerifyRSPem(data, key: string, sig: openarray[byte], alg: ptr HashClass, hashOid: cstring, hashLen: int): bool =
  # Step 1. Extract RSA key from `key` in PEM format
  var pkCtx: PkeyDecoderContext
  decodeFromPem(pkCtx, key)
  if pkeyDecoderKeyType(addr pkCtx) != KEYTYPE_RSA:
    invalidPemKey()
  template publicKey(): RsaPublicKey = pkCtx.key.rsa

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let s = rsaPkcs1VrfyGetDefault()
  var digest2: array[64, byte]

  if s(unsafeAddr sig[0], sig.len.uint, cast[ptr byte](hashOid), hashLen.uint, addr publicKey, addr digest2[0]) != 1:
    return false

  digest == digest2


#--------------------------------------
# jwt main
#--------------------------------------

type
  InvalidToken* = object of ValueError

  JWT* = object
    headerB64: string
    claimsB64: string
    header*: JsonNode
    claims*: JsonNode
    signature*: seq[byte]


proc splitToken(s: string): seq[string] =
  let parts = s.split(".")
  if parts.len != 3:
    raise newException(InvalidToken, "Invalid token")
  result = parts

proc initJWT*(header: JsonNode, claims: JsonNode, signature: seq[byte] = @[]): JWT =
  JWT(
    headerB64: header.toBase64,
    claimsB64: claims.toBase64,
    header: header,
    claims: claims,
    signature: signature
  )

# Load up a b64url string to JWT
proc toJWT*(s: string): JWT =
  var parts = splitToken(s)
  let
    headerB64 = parts[0]
    claimsB64 = parts[1]
    headerJson = parseJson(decodeUrlSafeAsString(headerB64))
    claimsJson = parseJson(decodeUrlSafeAsString(claimsB64))
    signature = decodeUrlSafe(parts[2])

  JWT(
    headerB64: headerB64,
    claimsB64: claimsB64,
    header: headerJson,
    claims: claimsJson,
    signature: signature
  )

proc toJWT*(node: JsonNode): JWT =
  initJWT(node["header"], node["claims"])

# Encodes the raw signature to b64url
proc signatureToB64(token: JWT): string =
  assert token.signature.len != 0
  result = encodeUrlSafe(token.signature)

proc loaded(token: JWT): string =
  token.headerB64 & "." & token.claimsB64

proc parsed(token: JWT): string =
  result = token.header.toBase64 & "." & token.claims.toBase64

# Signs a string with a secret
proc signString(toSign: string, secret: string): seq[byte] =
  template rsSign(hc, oid: typed, hashLen: int): seq[byte] =
    bearSignRSPem(toSign, secret, addr hc, oid, hashLen)
  return rsSign(sha256Vtable, HASH_OID_SHA256, sha256SIZE)

# Verify that the token is not tampered with
proc verifySignature(data: string, signature: seq[byte], secret: string): bool =
  result = bearVerifyRSPem(data, secret, signature, addr sha256Vtable, HASH_OID_SHA256, sha256SIZE)

proc sign*(token: var JWT, secret: string) =
  assert token.signature.len == 0
  token.signature = signString(token.parsed, secret)

# Verify a token typically an incoming request
proc verify*(token: JWT, secret: string): bool =
  verifySignature(token.loaded, token.signature, secret)

proc toString(token: JWT): string =
  token.header.toBase64 & "." & token.claims.toBase64 & "." & token.signatureToB64

proc `$`*(token: JWT): string =
  token.toString

proc `%`*(token: JWT): JsonNode =
  let s = $token
  %s
