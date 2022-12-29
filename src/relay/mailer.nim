import std/json
import std/logging
import std/os
import std/strformat
import std/strutils

import ./httpreq
import chronos

const usepostmark = defined(usepostmark)
const fromEmail {.strdefine.} = "relay@budgetwithbuckets.com"
when usepostmark:
  const POSTMARK_API_KEY {.strdefine.} = "env:POSTMARK_API_KEY"
  static: echo "POSTMARK_API_KEY: " & POSTMARK_API_KEY & "<--"
proc valueRef(location: string): string =
  ## Get a value from the given location. `location` is a string
  ## prefixed with one of the following, which determines where
  ## the value comes from:
  runnableExamples:
    assert getValue("env:FOO") == getEnv("FOO")
    assert getValue("embed:someval") == "someval"
  if location.startsWith("env:"):
    getEnv(location.substr("env:".len))
  elif location.startsWith("embed:"):
    location.substr("embed:".len)
  else:
    raise ValueError.newException("Unknown variable ref type")

proc sendEmail*(toEmail, subject, text: string) {.async.} =
  when usepostmark:
    let data = $(%* {
      "From": fromEmail,
      "To": toEmail,
      "Subject": subject,
      "MessageStream": "outbound",
      "TextBody": text,
    })
    var headers = HttpTable.init()
    headers.add("Accept", "application/json")
    headers.add("Content-Type": "application/json")
    headers.add("X-Postmark-Server-Token", POSTMARK_API_KEY.valueRef)
    let (code, res) = request("https://api.postmarkapp.com/email", MethodPost, data, headers = headers)
    if code != 200:
      error "Error sending email: " & $res
  else:
    # logging only
    info &"EMAIL FAKE SENDER:\nFrom: {fromEmail}\nTo: {toEmail}\nSubject: {subject}\n\n{text}\n------------------------------------"
    stderr.flushFile()
