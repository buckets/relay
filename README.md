[![.github/workflows/main.yml](https://github.com/buckets/relay/actions/workflows/main.yml/badge.svg)](https://github.com/buckets/relay/actions/workflows/main.yml)

![Buckets Relay Server Logo](./src/static/favicon.png)

# Buckets Relay Server

This repository contains the open source code for the [Buckets](https://www.budgetwithbuckets.com) relay server, which allows users to share budget data between their devices in an end-to-end encrypted way.

You can use the publicly available relay at <https://relay.budgetwithbuckets.com>

## Quickstart w/ Docker/Podman

If you want to run the relay on with docker:

1. Get the code:

```
git clone https://github.com/buckets/relay.git buckets-relay.git
cd buckets-relay.git
```

2. Build the image

```
docker build -f docker/Dockerfile -t buckets/relay .
```

3. Run it:

```
docker run -it --rm -p 8080:8080 buckets/relay
```

Read `docker/Dockerfile` to get an idea of how to build it yourself if you'd like.

## Security

- You should ensure that connections to this relay server are made with TLS.
- This relay server can see all traffic, so clients should encrypt data intended for other clients.
- Clients should also authenticate each other through the relay and not trust the authentication done by this server.

## Protocol

Relay clients communicate with the relay server using the following protocol. See [./src/proto2.nim](./src/proto2.nim) for more information.

In summary, devices connect with websockets and exchange messages. Messages sent from client to server are called *commands*. Messages sent from server to client are called *events*.

### Authentication

Clients authenticate with the server using a public/private key. A single person may have multiple public/private keys; typically one for each device.

### Client Commands

Clients send the following commands:

| Command        | Description |
|----------------|-------------|
| `Iam`          | In response to a `Who` event, proves that this client has the private key and does some spam mitigation |
| `PublishNote`  | Send a few bytes to another client addressed by topic (good for key exchange) |
| `FetchNote`    | Request a note addressed by topic |
| `SendData`     | Store/forward bytes to other clients, addressed by relay-authenticated public keys |
| `StoreChunk`   | Store bytes for other clients to fetch addressed by key and public key. |
| `GetChunk`     | Request stored chunk |
| `ChunksPresent` | Ask which chunks exist |


### Server Events

The relay server sends the following events:

| Event           | Description                        |
|-----------------|------------------------------------|
| `Okay`          | Sent when certain commands succeed |
| `Error`         | Sent when commands fail |
| `Who`           | Challenge for authenticating a client's public/private keys and spam mitigation |
| `Note`          | Data payload of a note requested by `FetchNote` |
| `Data`          | Data payload from another client, addressed by relay-authenticated public key |
| `Chunk`         | Data payload response to `GetChunk` request |
| `ChunkStatus`   | Response to `ChunksPresent` indicating which chunks exist/don't |

### Authentication

Authentication happens like this:

1. On connection, server sends `Who(challenge=ABCD...)`
2. Client responds with a signed PoW hash `Iam(pubkey=MYPK..., signature=SIGN...)`
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

### Data

There are 3 ways clients can exchange data:

1. Notes - public notes that are accessed by knowing the note *topic*. Notes are a good way to do key exchange. Notes expire after a short time.
2. Messages - ordered, stored-and-forwarded messages sent from one client to another client. These are automatically sent to a client upon connection, and deleted when sent. Messages expire after a while.
3. Chunks - clients store chunks with a string *key* and choose which clients (by their public key) are allowed to fetch uploaded chunks. Chunks may be overwritten. Chunks expire a while after their last update.

All forms of exchanging data are unreliable. Build with that in mind.

#### Notes

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

#### Messages

1. Alice sends `SendData(dst=BOBPK, data=hello)`
2. Server sends to Bob `Data(src=ALICEPK, data=hello)`

```
Alice             Relay              Bob
  │                 │                 │
  ├───Authenticated─┼─Authenticated───┤
  │                 │                 │
  │ SendData(Bob)   │                 │
  ├────────────────►│ Data(Alice)     │
  │                 ├────────────────►│
  │                 │                 │
```

#### Chunks

1. Alice sends `StoreChunk(dst=[BOBPK], key=apple, val=seed)`
2. Bob sends `GetChunks(src=ALICEPK, keys=[apple])`
3. Server sends `Chunk(src=ALICEPK, key=apple, val=seed)`

```
Alice                 Relay                 Bob
  │                     │                    │
  ├───────Authenticated─|─Authenticated──────┤
  │                     │                    │
  │ StoreChunk(apple)   |                    │
  ├────────────────────►│ GetChunks([apple]) |
  │                     │◄───────────────────┤
  │                     │                    │
  │                     │ Chunk(apple)       │
  │                     │───────────────────►│
  │                     │                    │
```
