# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import tables
import sets; export sets
import strformat
import strutils
import base64
import options
import libsodium/sodium
import logging
import ndb/sqlite

template TODO*(msg: string) =
  when defined(release): {.error: msg .}

type
  PublicKey* = distinct string
  SecretKey* = distinct string

  KeyPair* = tuple
    pk: PublicKey
    sk: SecretKey

  ## Relay event types
  EventKind* = enum
    Who = "?"
    Authenticated = "+"
    Connected = "c"
    Disconnected = "x"
    Data = "d"
    ErrorEvent = "E"
  
  ## Relay events -- server to client message
  RelayEvent* = object
    case kind*: EventKind
    of Who:
      who_challenge*: string
    of Authenticated:
      discard
    of Connected:
      conn_pubkey*: PublicKey
      conn_id*: int
    of Disconnected:
      dcon_pubkey*: PublicKey
      dcon_id*: int
    of Data:
      data*: string
      sender_id*: int
    of ErrorEvent:
      err_message*: string

  ## Relay command types
  CommandKind* = enum
    Iam = "i"
    Connect = "c"
    Disconnect = "x"
    SendData = "d"
  
  ## Relay command - client to server message
  RelayCommand* = object
    case kind*: CommandKind
    of Iam:
      iam_signature*: string
      iam_pubkey*: PublicKey
    of Connect:
      conn_pubkey*: PublicKey
    of Disconnect:
      dcon_id*: int
    of SendData:
      send_data*: string
      send_id*: int
  
  RelayClient = concept rc
    rc.sendEvent(RelayEvent)
  
  ClientWrap[T: RelayClient] = ref object
    obj: T
    client_id: int
    challenge: string
    pubkey: PublicKey
    connections: HashSet[int]

  Relay*[T: RelayClient] = ref object
    nextid: int
    clients: TableRef[int, ClientWrap[T]]
    db: DbConn

proc newRelay*[T](): Relay[T] =
  new(result)
  result.clients = newTable[int, ClientWrap[T]]()
  result.db = open(":memory:", "", "", "")
  let db = result.db
  db.exec(sql"""CREATE TABLE pending_conns (
    src_pk TEXT,
    dst_pk TEXT,
    PRIMARY KEY (src_pk, dst_pk)
  )""")
  db.exec(sql"""CREATE TABLE clients (
    client_id INTEGER,
    pubkey TEXT,
    PRIMARY KEY (client_id, pubkey)
  )""")

proc `$`*(wrap: ClientWrap): string =
  result.add "[" & $wrap.client_id & ":"
  if wrap.pubkey.string == "":
    result.add "----"
  else:
    result.add encode(wrap.pubkey.string)
  result.add "]"

proc `$`*(a: PublicKey): string =
  a.string.encode()

proc `==`*(a, b: PublicKey): bool {.borrow.}

proc `==`*(a, b: RelayEvent): bool =
  if a.kind != b.kind:
    return false
  else:
    case a.kind
    of Who:
      return a.who_challenge == b.who_challenge
    of Authenticated:
      return true
    of Connected:
      return a.conn_id == b.conn_id and a.conn_pubkey == b.conn_pubkey
    of Disconnected:
      return a.dcon_id == b.dcon_id and a.dcon_pubkey == b.dcon_pubkey
    of Data:
      return a.sender_id == b.sender_id and a.data == b.data
    of ErrorEvent:
      return a.err_message == b.err_message

proc `==`*(a, b: RelayCommand): bool =
  if a.kind != b.kind:
    return false
  else:
    case a.kind:
    of Iam:
      return a.iam_signature == b.iam_signature and a.iam_pubkey == b.iam_pubkey
    of Connect:
      return a.conn_pubkey == b.conn_pubkey
    of Disconnect:
      return a.dcon_id == b.dcon_id
    of SendData:
      return a.send_data == b.send_data and a.send_id == b.send_id

when defined(testmode):
  proc dump*(relay: Relay): string =
    for row in relay.db.getAllRows(sql"SELECT * FROM clients"):
      result.add $row & "\l"
    for row in relay.db.getAllRows(sql"SELECT * FROM pending_conns"):
      result.add $row & "\l"
  
  proc testmode_clients*[T](relay: Relay[T]): TableRef[int, ClientWrap[T]] =
    relay.clients

  proc testmode_connections*(wrap: ClientWrap): HashSet[int] =
    wrap.connections


proc newWrap*[T](obj: T): ClientWrap[T] =
  new(result)
  result.obj = obj
  result.connections = initHashSet[int]()

template sendEvent*(wrap: ClientWrap, ev: RelayEvent) =
  debug ">" & $ev
  wrap.obj.sendEvent(ev)

template sendError*(wrap: ClientWrap, message: string) =
  wrap.sendEvent(RelayEvent(
    kind: ErrorEvent,
    err_message: message,
  ))

proc connectPair*[T](a: var ClientWrap[T], b: var ClientWrap[T]) =
  ## Connect two clients together
  a.connections.incl(b.client_id)
  b.connections.incl(a.client_id)
  # info &"<conn {a} -> {b}"
  a.sendEvent(RelayEvent(kind: Connected, conn_pubkey: b.pubkey, conn_id: b.client_id))
  # info &"<conn {b} -> {a}"
  b.sendEvent(RelayEvent(kind: Connected, conn_pubkey: a.pubkey, conn_id: a.client_id))

proc addConnRequest*(relay: var Relay, alice_id: int, bob_pubkey: PublicKey) =
  ## Add or fulfil a connection request.
  var alice = relay.clients[alice_id]
  let db = relay.db

  # are they already connected
  if alice.connections.len > 0:
    var query = sql("SELECT * FROM clients WHERE pubkey = ? AND client_id IN (" & "?".repeat(alice.connections.len).join(",") & ")")
    var args = @[dbValue(bob_pubkey.string)]
    for conn in alice.connections.items:
      args.add(dbValue(conn))
    let row = relay.db.getRow(query, args)
    if row.isSome:
      # already connected
      return
  var row = relay.db.getRow(sql"""SELECT
      a.client_id,
      b.client_id
    FROM
      pending_conns as p
      left join clients as a
        on p.src_pk = a.pubkey
      left join clients as b
        on p.dst_pk = b.pubkey
    WHERE
      p.src_pk = ?
      AND p.dst_pk = ?
  """, [dbValue(bob_pubkey.string), dbValue(alice.pubkey.string)])
  if row.isSome:
    # mutual connection requests
    relay.db.exec(sql"DELETE FROM pending_conns WHERE src_pk = ? AND dst_pk = ?",
      [dbValue(bob_pubkey.string), dbValue(alice.pubkey.string)])
    let bob_id = row.get()[0].i.int
    var bob = relay.clients[bob_id]
    connectPair(alice, bob)
  else:
    # wait for bob to respond
    relay.db.exec(sql"INSERT INTO pending_conns (src_pk, dst_pk) VALUES (?, ?)",
      [dbValue(alice.pubkey.string), dbValue(bob_pubkey.string)])
    # row = relay.db.getRow(sql"SELECT client_id FROM clients WHERE pubkey = ?", [dbValue(bob_pubkey.string)])
    # if row.isSome:
    #   let bob_id = row.get()[0].i.int
    #   var bob = relay.clients[bob_id]
    #   bob.sendEvent(RelayEvent(kind: Knock, knock_pubkey: alice.pubkey))

proc disconnect*(me, other: var ClientWrap) =
  ## Remove me from other's connections
  other.connections.excl(me.client_id)
  other.sendEvent(RelayEvent(kind: Disconnected, dcon_id: me.client_id, dcon_pubkey: me.pubkey))

proc handleCommand*(relay: var Relay, src: int, command: RelayCommand) =
  debug &"<command {src} {command}"
  var client = relay.clients[src]
  defer:
    relay.clients[src] = client
  case command.kind
  of Iam:
    if client.challenge == "":
      client.sendError "Authentication cannot proceed. Reconnect and try again."
    try:
      crypto_sign_verify_detached(command.iam_pubkey.string, client.challenge, command.iam_signature)
    except:
      client.challenge = "" # disable authentication
      client.sendError "Invalid signature"
      return
    client.pubkey = command.iam_pubkey
    relay.db.exec(sql"UPDATE clients SET pubkey = ? WHERE client_id = ?",
      [dbValue(client.pubkey.string), dbValue(src)])
    client.sendEvent(RelayEvent(
      kind: Authenticated,
    ))
    # # Check for pending knocks
    # for row in relay.db.getAllRows(sql"""SELECT
    #       a.client_id
    #     FROM
    #       pending_conns as p
    #       left join clients as a
    #         on p.src_pk = a.pubkey
    #     WHERE
    #       p.dst_pk = ?
    #   """, [dbValue(client.pubkey.string)]):
    #   let alice_id = row[0].i.int
    #   var alice = relay.clients[alice_id]
    #   debug &"<knck {alice} -> {client}"
    #   client.sendEvent(RelayEvent(kind: Knock, knock_pubkey: alice.pubkey))
  of Connect:
    if client.pubkey.string == "":
      client.sendError "Connection forbidden"
    elif command.conn_pubkey.string == client.pubkey.string:
      client.sendError "Can't connect to self"
    else:
      # info &">conn {client} -> " & encode(command.conn_pubkey.string)
      relay.addConnRequest(src, command.conn_pubkey)
  of Disconnect:
    if command.dcon_id notin client.connections:
      client.sendError "No such connection"
    else:
      var other = relay.clients[command.dcon_id]
      client.disconnect(other)
      other.disconnect(client)
  of SendData:
    if client.pubkey.string == "":
      client.sendError "Sending forbidden"
    elif command.send_id notin client.connections:
      client.sendError "No such connection"
    else:
      let remote = relay.clients[command.send_id]
      remote.sendEvent(RelayEvent(
        kind: Data,
        sender_id: src,
        data: command.send_data,
      ))

template sendData*(relay: var Relay, from_id: int, to_id: int, data: string) =
  relay.handleCommand(from_id, RelayCommand(kind: SendData, send_data: data, send_id: to_id))

proc add*[T](relay: var Relay[T], client: T): int =
  ## Add a new client to the Relay, initiating authentication
  ## Returns the client id
  var wrap = newWrap[T](client)
  wrap.client_id = relay.nextid
  relay.nextid.inc()
  wrap.challenge = randombytes(32)
  relay.db.exec(sql"INSERT INTO clients (client_id) VALUES (?)", [dbValue(wrap.client_id)])
  TODO "Protect against overwriting existing values in .clients"
  relay.clients[wrap.client_id] = wrap
  wrap.sendEvent(RelayEvent(
    kind: Who,
    who_challenge: wrap.challenge,
  ))
  result = wrap.client_id

proc removeClient*[T](relay: var Relay[T], client_id: int): bool =
  ## Remove a client from the relay if it exists.
  ## Returns true if it was removed, false if it wasn't there
  ## to begin with.
  var client: ClientWrap[T]
  result = relay.clients.pop(client_id, client)
  if result:
    relay.db.exec(sql"DELETE FROM pending_conns WHERE src_pk = ? OR dst_pk = ?",
      [dbValue(client.pubkey.string), dbValue(client.pubkey.string)])
    for other_id in client.connections:
      var other = relay.clients[other_id]
      client.disconnect(other)

#------------------------------------------------------------
# utilities
#------------------------------------------------------------
proc genkeys*(): KeyPair =
  let (pk, sk) = crypto_sign_keypair()
  result = (pk.PublicKey, sk.SecretKey)

proc sign*(key: SecretKey, message: string): string =
  ## Sign a message with the given secret key
  result = crypto_sign_detached(key.string, message)
