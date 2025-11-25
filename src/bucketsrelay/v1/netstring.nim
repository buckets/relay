import std/deques
import std/strformat
import std/strutils

type
  NSDecoderState = enum
    LookingForNumber,
    ReadingData,
    LookingForComma,
  NetstringDecoder* = object
    buf: string
    expectedLen: int
    state: NSDecoderState
    maxlen: int
    output: Deque[string]
    terminalChar*: char

const
  COLONCHAR = ':'
  TERMINALCHAR = ','
  DEFAULTMAXLEN = 1_000_000

proc nsencode*(msg:string, terminalChar = TERMINALCHAR):string {.inline.} =
  $msg.len & COLONCHAR & msg & terminalChar

proc newNetstringDecoder*(terminalChar = TERMINALCHAR):NetstringDecoder =
  result.output = initDeque[string]()
  result.terminalChar = terminalChar
  result.maxlen = DEFAULTMAXLEN

when defined(testmode):
  proc reset*(p: var NetstringDecoder) =
    ## Reset the parser.  For testing only.
    p.buf = ""
    p.expectedLen = 0
    p.state = LookingForNumber

proc `maxlen=`*(p: var NetstringDecoder, length:int) =
  ## Set the maximum message length
  p.maxlen = length

proc `len`*(p: var NetstringDecoder):int =
  p.output.len

proc consume*(p: var NetstringDecoder, data:string) =
  ## Send some netstring data (perhaps incomplete as yet)
  var cursor:int = 0
  while cursor < data.len:
    case p.state:
    of LookingForNumber:
      let ch = data[cursor]
      cursor.inc()
      case ch
      of '0'..'9':
        p.buf.add(ch)
        if p.buf.len == 2 and p.buf[0] == '0':
          raise newException(ValueError, &"Length may not start with 0")
        if p.maxlen != 0:
          if p.buf.parseInt() > p.maxlen:
            raise newException(ValueError, &"Message too long")
      of COLONCHAR:
        p.expectedLen = p.buf.parseInt()
        p.buf = ""
        if p.expectedLen == 0:
          p.state = LookingForComma
        else:
          p.state = ReadingData
      else:
        raise newException(ValueError, &"Invalid netstring length char: {ch.repr}")
      
    of ReadingData:
      let toread = p.expectedLen - int(p.buf.len)
      var sidx = cursor
      var eidx = sidx + toread - 1
      if eidx >= int(data.len):
        eidx = int(data.len-1)
      let snippet = data[sidx..eidx]

      p.buf.add(snippet)
      cursor += toread
      if int(p.buf.len) == p.expectedLen:
        # message possibly complete
        p.state = LookingForComma
    of LookingForComma:
      let ch = data[cursor]
      cursor.inc()
      if ch == p.terminalChar:
        # message complete!
        # Is this a copy?  I'd rather it be a move
        let msg = p.buf
        p.buf = ""
        p.output.addLast(msg)
        p.state = LookingForNumber
      else:
        raise newException(ValueError, &"Missing terminal comma")

proc bytesToRead*(p: var NetstringDecoder): int =
  ## Return how many bytes the decoder needs to read
  case p.state
  of LookingForNumber:
    return 1
  of LookingForComma:
    return 1
  of ReadingData:
    return p.expectedLen - int(p.buf.len)

proc hasMessage*(p: var NetstringDecoder): bool =
  return p.output.len > 0

proc nextMessage*(p: var NetstringDecoder): string =
  ## Get the next decoded message
  if p.output.len > 0:
    p.output.popFirst()
  else:
    raise newException(IndexError, &"No message available")

