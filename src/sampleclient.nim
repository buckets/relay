import std/asyncdispatch
import std/options

import ws

import ./objs
import ./proto2
import ./server2

export KeyPair, genkeys, NetstringSocket

proc newWS*(url: string): NetstringSocket =
  let ws = waitFor newWebSocket(url)
  return newNetstringSocket(ws)

proc newRelayClient*(url: string, keys: KeyPair): NetstringSocket =
  var ns = newWS(url)
  let who = waitFor ns.receiveMessage()
  let answer = who.who_challenge.answer(keys.sk)
  waitFor ns.sendCommand(RelayCommand(kind: Iam, iam_answer: answer, iam_pubkey: keys.pk))
  let ok = waitFor ns.receiveMessage()
  doAssert ok.kind == Okay, $ok
  return ns

proc publishNote*(ns: NetstringSocket, topic: string, data: string) {.async.} =
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

proc fetchNote*(ns: NetstringSocket, topic: string): Future[string] {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: FetchNote,
    fetch_topic: topic,
  ))
  let res = await ns.receiveMessage()
  if res.kind == Note:
    return res.note_data
  else:
    raise ValueError.newException("No such note: " & topic)

proc sendData*(ns: NetstringSocket, dst: PublicKey, val: string) {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: SendData,
    send_dst: dst,
    send_val: val,
  ))

proc getData*(ns: NetstringSocket): Future[string] {.async.} =
  let res = await ns.receiveMessage()
  if res.kind == Data:
    return res.data_val
  else:
    raise ValueError.newException("Expecting Data but got: " & $res)

proc storeChunk*(ns: NetstringSocket, dsts: seq[PublicKey], key: string, val: string) {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: StoreChunk,
    chunk_dst: dsts,
    chunk_key: key,
    chunk_val: val,
  ))

proc getChunk*(ns: NetstringSocket, src: PublicKey, key: string): Future[Option[string]] {.async.} =
  await ns.sendCommand(RelayCommand(
    kind: GetChunks,
    chunk_src: src,
    chunk_keys: @[key],
  ))
  let res = await ns.receiveMessage()
  if res.kind == Chunk:
    return res.chunk_val
  else:
    raise ValueError.newException("Expecing Chunk but got: " & $res)
