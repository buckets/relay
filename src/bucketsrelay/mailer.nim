import std/logging
import std/os
import std/strformat
import std/strutils

import chronos

import ./common

const usepostmark = multiusermode and not defined(nopostmark)
const fromEmail {.strdefine.} = "relay@budgetwithbuckets.com"
when usepostmark:
  const POSTMARK_API_KEY {.strdefine.} = "env:POSTMARK_API_KEY"

  import std/json
  import ./httpreq
  

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

proc sendEmail*(toEmail, subject, text: string) {.async, raises: [CatchableError].} =
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
    headers.add("Content-Type", "application/json")
    headers.add("X-Postmark-Server-Token", POSTMARK_API_KEY.valueRef)
    let (code, res) = await request("https://api.postmarkapp.com/email", MethodPost, data, headers = headers)
    if code != 200:
      try:
        error "Error sending email: " & $res
      except:
        discard
      raise CatchableError.newException("Email sending failed")
  else:
    # logging only
    info "EMAIL FAKE SENDER:\nFrom: " & fromEmail & "\nTo: " & toEmail & "\nSubject: " & subject & "\n\n" & text & "\n------------------------------------"
    stderr.flushFile()
