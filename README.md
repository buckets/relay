[![.github/workflows/main.yml](https://github.com/buckets/relay/actions/workflows/main.yml/badge.svg)](https://github.com/buckets/relay/actions/workflows/main.yml)

![Buckets Relay Server Logo](./src/static/favicon.png)

# Buckets Relay Server

This repository contains the open source code for the [Buckets](https://www.budgetwithbuckets.com) relay server, which allows users to share budget data between their devices in an end-to-end encrypted way.

You can use the publicly available relay at <https://relay.budgetwithbuckets.com>

## Quickstart

If you want to run the relay on your own computer, do the following:

1. Install [Nim](https://nim-lang.org/)
2. Get the code:

```
git clone https://github.com/buckets/relay.git buckets-relay.git
cd buckets-relay.git
```

3. Install dependencies

```
nimble install https://github.com/iffy/pkger/
pkger fetch
```

4. Run the server:

TODO:

```sh
nim r src/brelay.nim server
```

This will launch the relay on the default port. Run with `--help` for more options.

## Security

- You should ensure that connections to this relay server are made with TLS.
- This relay server can see all traffic, so clients should encrypt data intended for other clients.
- Clients should also authenticate each other through the relay and not trust the authentication done by this server.

## Development

TODO:

To run the server locally:

```sh
nimble run brelay server
```

## Deployment to fly.io

If you'd like to run a relay server on [fly.io](https://fly.io/), sign up for the service then do one of the following. If you'd like to host somewhere else, you could use the Dockerfiles in [docker/](./docker/) as a starting point.

TODO:

### Single-user mode

```sh
fly launch --dockerfile docker/singleuser.Dockerfile
```

### Multi-user mode

```sh
fly launch --dockerfile docker/multiuser.Dockerfile
```

## Protocol

Relay clients communicate with the relay server using the following protocol. See [./src/bucketsrelay/proto.nim](./src/bucketsrelay/proto.nim) for more information, and [./src/bucketsrelay/stringproto.nim](./src/bucketsrelay/stringproto.nim) for encoding details.

In summary, devices connect with websockets and exchange messages. Messages sent from client to server are called commands. Messages sent from server to client are called events.

### Authentication

Clients authenticate with the server with a public/private key. A single person may have multiple public/private keys; typically one for each device.

### Client Commands

Clients send the following commands:

| Command        | Description |
|----------------|-------------|
| `Iam`          | In response to a `Who` event, proves that this client has the private key |
| `PublishNote`  | Send a few bytes to another client addressed by topic (good for key exchange) |
| `FetchNote`    | Request a note addressed by topic |
| `SendData`     | Store/forward bytes to another client, addressed by relay-authenticated public key |

### Server Events

The relay server sends the following events:

| Event           | Description |
|-----------------|-------------|
| `Okay`          | Sent when certain commands succeed |
| `Error`         | Sent when commands fail |
| `Who`           | Challenge for authenticating a client's public/private keys |
| `Note`          | Data payload of a note requested by `FetchNote` |
| `Data`          | Data payload from another client, addressed by relay-authenticated public key |

### Sequences and Usage

#### Authentication

Authentication happens like this:

1. On connection, server sends `Who(challenge=ABCD...)`
2. Client responds with `Iam(pubkey=MYPK..., signature=SIGN...)`
3. If the signature is correct, server sends `Okay(cmd=Iam)`

```
Client           Relay
 │                 │
 │             Who │
 │◄────────────────┤
 │                 │
 │ Iam             │
 ├────────────────►│
 │                 │
 │            Okay │
 │◄────────────────┤
 │                 │
```

#### Notes

After authenticating, clients can send each other short notes, addressed by a string *topic*. Each note expires after a time and will only ever been sent to one client who. The `FetchNote` command may be sent before or after the note is published. It works like this:

1. Alice sends `PublishNote(topic=apple, data=something)`
2. Bob sends `FetchNote(topic=apple)`
3. Server sends to Bob `Note(topic=apple, data=something)` 

```
Alice                 Relay                 Bob
  │                     │                    │
  ├───────Authenticated─|─Authenticated──────┤
  │                     │                    │
  │ PublishNote(apple)  |                    │
  ├────────────────────►│   FetchNote(apple) |
  │                     │◄───────────────────┤
  │                     │                    │
  │                     │ Note(apple)        │
  │                     │───────────────────►│
  │                     │                    │
```

#### Data

After authenticating, clients may send data to be stored and forwarded to clients next time they connect. Stored data expires after a time. In other words, the transport is unreliable by design.

Here's how it works:

1. Alice sends `SendData(dst=BOBPK, data=hello)`
2. Server sends to Bob `Data(src=ALICEPK, data=hello)`

```
Alice             Relay              Bob
  │                 │                 │
  ├───Authenticated─┼─Authenticated───┤
  │                 │                 │
  │SendData(Bob)    │                 │
  ├────────────────►│ Data(Alice)     │
  │                 ├────────────────►│
  │                 │                 │
```

