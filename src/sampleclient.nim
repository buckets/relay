import std/asyncdispatch
import std/logging
import std/options

import ws

import ./objs
import ./proto2

type
  NetstringClient* = ref object
    buf: string
    socket: WebSocket

proc newNetstringClient*(sock: WebSocket): NetstringClient =
  new(result)
  result.socket = sock

proc receiveString*(ns: NetstringClient): Future[string] {.async.} =
  while true:
    try:
      return ns.buf.nschop()
    except IncompleteNetstring:
      discard
    let packet = await ns.socket.receiveStrPacket()
    ns.buf &= packet  

proc sendString*(ns: NetstringClient, msg: string): Future[void] {.async.} =
  await ns.socket.send(nsencode(msg))

proc sendCommand*(ns: NetstringClient, cmd: RelayCommand): Future[void] {.async.} =
  when LOG_COMMS:
    info "[client] -> " & $cmd
  await ns.sendString(cmd.serialize())

proc receiveMessage*(ns: NetstringClient): Future[RelayMessage] {.async.} =
  let s = await ns.receiveString()
  let res = RelayMessage.deserialize(s)
  when LOG_COMMS:
    info "[client] <- " & $res
  return res  

proc newNetstringClient*(url: string): NetstringClient =
  let ws = waitFor newWebSocket(url)
  return newNetstringClient(ws)

proc newRelayClient*(url: string, keys: KeyPair): NetstringClient =
  var ns = newNetstringClient(url)
  let who = waitFor ns.receiveMessage()
  let answer = who.who_challenge.answer(keys.sk)
  waitFor ns.sendCommand(RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: keys.pk))
  let ok = waitFor ns.receiveMessage()
  doAssert ok.kind == Okay, $ok
  return ns

proc publishNote*(ns: NetstringClient, topic: string, data: string) {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: PublishNote,
    pub_topic: topic,
    pub_data: data,
  ))
  let res = await ns.receiveMessage()
  if res.kind == Okay:
    discard
  elif res.kind == Error:
    raise ValueError.newException("Error publishing note: " & $res.err_code & " " & res.err_message)

proc fetchNote*(ns: NetstringClient, topic: string): Future[string] {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: FetchNote,
    fetch_topic: topic,
  ))
  let res = await ns.receiveMessage()
  if res.kind == Note:
    return res.note_data
  else:
    raise ValueError.newException("No such note: " & topic)

proc sendData*(ns: NetstringClient, dst: PublicKey, val: string) {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: SendData,
    send_dst: dst,
    send_val: val,
  ))

proc getData*(ns: NetstringClient): Future[string] {.async.} =
  let res = await ns.receiveMessage()
  if res.kind == Data:
    return res.data_val
  else:
    raise ValueError.newException("Expecting Data but got: " & $res)

proc storeChunk*(ns: NetstringClient, dsts: seq[PublicKey], key: string, val: string) {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: StoreChunk,
    chunk_dst: dsts,
    chunk_key: key,
    chunk_val: val,
  ))

proc getChunk*(ns: NetstringClient, src: PublicKey, key: string): Future[Option[string]] {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: GetChunks,
    chunk_src: src,
    chunk_keys: @[key],
  ))
  let res = await ns.receiveMessage()
  if res.kind == Chunk:
    return res.chunk_val
  else:
    raise ValueError.newException("Expecting Chunk but got: " & $res)

proc hasChunk*(ns: NetstringClient, src: PublicKey, key: string): Future[bool] {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: HasChunks,
    has_src: src,
    has_keys: @[key],
  ))
  let res = await ns.receiveMessage()
  if res.kind == ChunkStatus:
    return key in res.present
  else:
    raise ValueError.newException("Expecting ChunkStatus but got: " & $res)
