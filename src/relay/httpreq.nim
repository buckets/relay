## HTTP client that does SSL/TLS with BearSSL (so you don't need `-d:ssl`)
## 
import std/strutils
import std/options
import std/uri

import chronos
import chronos/apps/http/httpclient
import chronos/apps/http/httpcommon; export HttpMethod

export waitFor

type
  HttpResponse* = tuple
    code: int
    body: string


proc fetch*(session: HttpSessionRef, req: HttpClientRequestRef): Future[HttpResponseTuple] {.async.} =
  ## Copied from nim-chronos
  var
    request = req
    response: HttpClientResponseRef = nil
    redirect: HttpClientRequestRef = nil

  while true:
    try:
      response = await request.send()
      if response.status >= 300 and response.status < 400:
        redirect =
          block:
            if "location" in response.headers:
              let location = response.headers.getString("location")
              if len(location) > 0:
                let res = request.redirect(parseUri(location))
                if res.isErr():
                  raiseHttpRedirectError(res.error())
                res.get()
              else:
                raiseHttpRedirectError("Location header with an empty value")
            else:
              raiseHttpRedirectError("Location header missing")
        discard await response.consumeBody()
        await response.closeWait()
        response = nil
        await request.closeWait()
        request = nil
        request = redirect
        request.headers.set(HostHeader, request.address.hostname)
        redirect = nil
      else:
        let data = await response.getBodyBytes()
        let code = response.status
        await response.closeWait()
        response = nil
        await request.closeWait()
        request = nil
        return (code, data)
    except CancelledError as exc:
      if not(isNil(response)): await closeWait(response)
      if not(isNil(request)): await closeWait(request)
      if not(isNil(redirect)): await closeWait(redirect)
      raise exc
    except HttpError as exc:
      if not(isNil(response)): await closeWait(response)
      if not(isNil(request)): await closeWait(request)
      if not(isNil(redirect)): await closeWait(redirect)
      raise exc

proc request*(url: string, meth: HttpMethod, body = "", headers = HttpTable.init()): Future[HttpResponse] {.async.} =
  ## High level request
  var session = HttpSessionRef.new()
  let address = session.getAddress(url).tryGet()
  var req = HttpClientRequestRef.new(session, address, meth,
    body = body.toOpenArrayByte(0, body.len-1),
    headers = headers.toList())
  let (code, bytes) = await session.fetch(req)
  return (code, bytes.bytesToString)

when isMainModule:
  import std/os
  import std/strformat
  let url = paramStr(1)
  echo &"requesting {url}"
  let resp = waitFor request(url, MethodGet)
  echo "resp: ", resp[0]
  echo resp[1]
