# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/base64
import std/hashes
import std/logging
import std/options
import std/sets; export sets
import std/strformat
import std/strutils
import std/tables

import libsodium/sodium
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
    of Disconnected:
      dcon_pubkey*: PublicKey
    of Data:
      data*: string
      sender_pubkey*: PublicKey
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
      dcon_pubkey*: PublicKey
    of SendData:
      send_data*: string
      dest_pubkey*: PublicKey
  
  RelayConnection*[T] = ref object
    challenge: string
    pubkey*: PublicKey
    peer_connections: HashSet[PublicKey]
    sender*: T

  Relay*[T] = ref object
    conns: TableRef[PublicKey, RelayConnection[T]]
    conn_requests: TableRef[PublicKey, seq[PublicKey]]
    db: DbConn

proc newRelay*[T](): Relay[T] =
  new(result)
  result.conns = newTable[PublicKey, RelayConnection[T]]()
  result.conn_requests = newTable[PublicKey, seq[PublicKey]]()

proc `$`*(a: PublicKey): string =
  a.string.encode()

proc abbr*(s: string, size = 6): string =
  if s.len > size:
    result.add s.substr(0, size) & "..."
  else:
    result.add(s)

proc abbr*(a: PublicKey): string =
  a.string.encode().abbr

proc `$`*(conn: RelayConnection): string =
  result.add "[RConn "
  if conn.pubkey.string == "":
    result.add "----------"
  else:
    result.add conn.pubkey.abbr
  result.add "]"

proc `==`*(a, b: PublicKey): bool {.borrow.}

proc hash*(p: PublicKey): Hash {.borrow.}

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
      return a.conn_pubkey == b.conn_pubkey
    of Disconnected:
      return a.dcon_pubkey == b.dcon_pubkey
    of Data:
      return a.sender_pubkey == b.sender_pubkey and a.data == b.data
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
      return a.dcon_pubkey == b.dcon_pubkey
    of SendData:
      return a.send_data == b.send_data and a.dest_pubkey == b.dest_pubkey

proc dbg*(ev: RelayEvent): string =
  result.add "("
  case ev.kind
  of Who:
    result.add "Who challenge=" & ev.who_challenge.encode().abbr
  of Authenticated:
    result.add "Authenticated"
  of Connected:
    result.add "Connected " & ev.conn_pubkey.abbr
  of Disconnected:
    result.add "Disconnected " & ev.dcon_pubkey.abbr
  of Data:
    result.add "Data " & ev.sender_pubkey.abbr & " data=" & $ev.data.len
  of ErrorEvent:
    result.add "Error " & ev.err_message
  else:
    discard
  result.add ")"

proc dbg*(cmd: RelayCommand): string =
  result.add "("
  case cmd.kind
  of Iam:
    result.add &"Iam {cmd.iam_pubkey.abbr} sig={cmd.iam_signature.encode.abbr}"
  of Connect:
    result.add &"Connect {cmd.conn_pubkey.abbr}"
  of Disconnect:
    result.add &"Disconnect {cmd.dcon_pubkey.abbr}"
  of SendData:
    result.add &"SendData {cmd.dest_pubkey.abbr} data={cmd.send_data.len}"
  result.add ")"

when defined(testmode):
  # proc dump*(relay: Relay): string =
  #   for row in relay.db.getAllRows(sql"SELECT * FROM clients"):
  #     result.add $row & "\l"
  #   for row in relay.db.getAllRows(sql"SELECT * FROM pending_conns"):
  #     result.add $row & "\l"
  
  proc testmode_conns*[T](relay: Relay[T]): TableRef[PublicKey, RelayConnection[T]] =
    relay.conns

  proc testmode_conns*(conn: RelayConnection): HashSet[PublicKey] =
    conn.peer_connections

proc newRelayConnection*[T](sender: T): RelayConnection[T] =
  new(result)
  result.sender = sender
  result.peer_connections = initHashSet[PublicKey]()

template sendEvent(conn: RelayConnection, ev: RelayEvent) =
  debug $conn & "<  " & ev.dbg
  conn.sender.sendEvent(ev)

template sendError(conn: RelayConnection, message: string) =
  debug $conn & "<  error: " & message
  conn.sender.sendEvent(RelayEvent(
    kind: ErrorEvent,
    err_message: message,
  ))

proc initAuth*[T](relay: var Relay[T], client: T): RelayConnection[T] =
  ## Ask the client to authenticat itself. After it succeeds, it will
  ## be added as a connected client.
  var conn = newRelayConnection[T](client)
  conn.challenge = randombytes(32)
  conn.sendEvent(RelayEvent(
    kind: Who,
    who_challenge: conn.challenge,
  ))
  return conn

proc connectPair[T](a, b: var RelayConnection[T]) =
  ## Connect two clients together
  a.peer_connections.incl(b.pubkey)
  b.peer_connections.incl(a.pubkey)
  a.sendEvent(RelayEvent(kind: Connected, conn_pubkey: b.pubkey))
  b.sendEvent(RelayEvent(kind: Connected, conn_pubkey: a.pubkey))

proc addConnRequest(relay: var Relay, alice_pubkey: PublicKey, bob_pubkey: PublicKey) =
  ## Add or fulfil a connection request.
  var alice = relay.conns[alice_pubkey]
  if bob_pubkey in alice.peer_connections:
    # They're already connected
    return
  
  var bob_requests = relay.conn_requests.getOrDefault(bob_pubkey, @[])
  if alice_pubkey in bob_requests:
    # They both want to connect. Connect them!
    bob_requests.delete(bob_requests.find(alice_pubkey))
    var bob = relay.conns[bob_pubkey]
    connectPair(alice, bob)
    return
  else:
    # Alice wants to connect with Bob, but he hasn't indicated
    # that he wants to connect yet.
    relay.conn_requests.mgetOrPut(alice_pubkey, @[]).add(bob_pubkey)

proc handleCommand*[T](relay: var Relay[T], conn: RelayConnection[T], command: RelayCommand) =
  debug &"{conn} > {command.dbg}"
  case command.kind
  of Iam:
    if conn.challenge == "":
      conn.sendError "Authentication cannot proceed. Reconnect and try again."
    try:
      crypto_sign_verify_detached(command.iam_pubkey.string, conn.challenge, command.iam_signature)
    except:
      conn.challenge = "" # disable authentication
      conn.sendError "Invalid signature"
      return
    conn.pubkey = command.iam_pubkey
    TODO "Handle the case where there's already a pubkey in here"
    relay.conns[conn.pubkey] = conn
    conn.sendEvent(RelayEvent(
      kind: Authenticated,
    ))
  of Connect:
    if conn.pubkey.string == "":
      conn.sendError "Connection forbidden"
    elif command.conn_pubkey.string == conn.pubkey.string:
      conn.sendError "Can't connect to self"
    else:
      relay.addConnRequest(conn.pubkey, command.conn_pubkey)
  of Disconnect:
    if command.dcon_pubkey notin conn.peer_connections:
      conn.sendError "No such connection"
    else:
      TODO "Handle the missing key case here"
      var other = relay.conns[command.dcon_pubkey]
      # disassociate
      other.peer_connections.excl(conn.pubkey)
      conn.peer_connections.excl(other.pubkey)
      # notify
      conn.sendEvent(RelayEvent(
        kind: Disconnected,
        dcon_pubkey: other.pubkey,
      ))
      other.sendEvent(RelayEvent(
        kind: Disconnected,
        dcon_pubkey: conn.pubkey,
      ))
  of SendData:
    if conn.pubkey.string == "":
      conn.sendError "Sending forbidden"
    elif command.dest_pubkey notin conn.peer_connections:
      conn.sendError "No such connection"
    else:
      TODO "Handle the missing key case here"
      let remote = relay.conns[command.dest_pubkey]
      remote.sendEvent(RelayEvent(
        kind: Data,
        sender_pubkey: conn.pubkey,
        data: command.send_data,
      ))

proc removeConnection*[T](relay: var Relay[T], conn: RelayConnection[T]) =
  ## Remove a conn from the relay if it exists.
  TODO "Handle socket disconnections gracefully"
  relay.conn_requests.del(conn.pubkey)
  # disconnect all peer connections
  var commands: seq[RelayCommand]
  for other_pubkey in conn.peer_connections:
    commands.add(RelayCommand(
      kind: Disconnect,
      dcon_pubkey: other_pubkey,
    ))
  for command in commands:
    relay.handleCommand(conn, command)
  # remove it from the registry
  relay.conns.del(conn.pubkey)

#------------------------------------------------------------
# utilities
#------------------------------------------------------------
proc genkeys*(): KeyPair =
  let (pk, sk) = crypto_sign_keypair()
  result = (pk.PublicKey, sk.SecretKey)

proc sign*(key: SecretKey, message: string): string =
  ## Sign a message with the given secret key
  result = crypto_sign_detached(key.string, message)
