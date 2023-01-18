## Asynchronous reading from stdin
## 
## The implementation may change. The important thing is that this works:
## 
## var reader = asyncStdinReader()
## let res = waitFor reader.read(10)
import std/deques
import chronos

const BUFSIZE = 4096.uint

type
  ReadResponse = uint

  AsyncStdinReader* = ref object
    outQ: AsyncQueue[string]
    inQ: AsyncQueue[uint]
    closed: bool
    thread: Thread[AsyncFD]

var requestCh: Channel[uint]
requestCh.open(0)

proc workerReadLoop(wfd: AsyncFD) {.thread.} =
  ## Run this in a thread other than the main one
  ## to get somewhat asynchronous IO
  let transp = fromPipe(wfd)
  var buf: array[BUFSIZE, char]
  var closed = false
  while not closed:
    let req = requestCh.recv()
    var toRead = req
    var didRead: uint = 0
    while toRead > 0:
      let toReadThisTime = min(BUFSIZE, toRead)
      let n = stdin.readBuffer(addr buf, toReadThisTime)
      if n == 0:
        closed = true
        break
      didRead.inc(n)
      toRead.dec(n)
      discard waitFor transp.write(addr buf, n)
  waitFor transp.closeWait()

proc mainReadLoop(reader: AsyncStdinReader, transp: StreamTransport) {.async.} =
  ## Run this companion loop of workerReadLoop in the main thread
  while true:
    let size = await reader.inQ.get()
    var ret = ""
    if not reader.closed:
      var toRead = size
      while toRead > 0 and not reader.closed:
        var data: seq[byte]
        try:
          data = await transp.read(toRead.int)
        except:
          discard
        if data.len == 0:
          reader.closed = true
          break
        for c in data:
          ret.add(chr(c))
        toRead.dec(data.len)
    reader.outQ.putNoWait(ret)

#---------------------------------------------------------------
# Public API
#---------------------------------------------------------------
proc asyncStdinReader*(): AsyncStdinReader =
  new(result)
  result.inQ = newAsyncQueue[uint]()
  result.outQ = newAsyncQueue[string]()
  let (rfd, wfd) = createAsyncPipe()
  let readTransp = fromPipe(rfd)
  result.thread.createThread(workerReadLoop, wfd)
  asyncSpawn result.mainReadLoop(readTransp)

proc read*(reader: AsyncStdinReader, size: uint): Future[string] {.async.} =
  requestCh.send(size)
  reader.inQ.putNoWait(size)
  return await reader.outQ.get()

template read*(reader: AsyncStdinReader, size: int): untyped =
  reader.read(size.uint)
