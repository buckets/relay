[![.github/workflows/main.yml](https://github.com/buckets/relay/actions/workflows/main.yml/badge.svg)](https://github.com/buckets/relay/actions/workflows/main.yml)

![Buckets Relay Server Logo](./src/static/favicon.png)

# Buckets Relay Server

This repository contains the open source code for the [Buckets](https://www.budgetwithbuckets.com) relay server, which allows users to share budget data between their devices in an end-to-end encrypted way.

## Quickstart - single user mode

If you want to run the relay on your own computer with only one user account, do the following:

1. Install [Nim](https://nim-lang.org/)
2. Run `nimble -d:relaysingleusermode install https://github.com/buckets/relay.git`
3. Run the server:

```sh
RELAY_USERNAME=someusername
RELAY_PASSWORD=somepassword
brelay server
```

This will launch the relay on the default port. Run `brelay --help` for more options.

## Multi-user mode

If you install/compile without `-d:relaysingleusermode` the server will run in multi-user mode.

Register users via `brelay adduser ...` or through the web interface.

Registration-related emails are sent through [Postmark](https://postmarkapp.com/). Set `POSTMARK_API_KEY` to your Postmark key to use it. Otherwise, disable emails with `-d:nopostmark`.

Users can authenticate with their Buckets license if you set an environment variable `AUTH_LICENSE_PUBKEY=<A PEM FORMATTED PUBKEY>`

## Security

- You should ensure that connections to this relay server are made with TLS.
- This relay server can see all traffic, so clients should encrypt data intended for other clients.
- Clients should also authenticate each other through the relay and not trust the authentication done by this server.

## Development

To run the server locally:

```sh
nimble run brelay server
```

## Deployment to fly.io

If you'd like to run a relay server on [fly.io](https://fly.io/), sign up for the service then do one of the following. If you'd like to host somewhere else, you could use the Dockerfiles in [docker/](./docker/) as a starting point.

### Single-user mode

```sh
fly launch --dockerfile docker/singleuser.Dockerfile
fly secrets set RELAY_USERNAME='someusername' RELAY_PASSWORD='somepassword'
```

| Variable | Description |
|---|---|
| `RELAY_USERNAME` | Username or email you'll use to authenticate to the relay. |
| `RELAY_PASSWORD` | Password you'll use to authenticate to the relay. |

### Multi-user mode

```sh
fly launch --dockerfile docker/multiuser.Dockerfile
fly secrets set POSTMARK_API_KEY='your key' AUTH_LICENSE_PUBKEY='the key' LICENSE_HASH_SALT='choose something here'
```

| Variable | Description |
|---|---|
| `POSTMARK_API_KEY` | API key from [Postmark](https://postmarkapp.com/) |
| `AUTH_LICENSE_PUBKEY` | RSA public key of Buckets licenses. If empty, license authentication is disabled. |
| `LICENSE_HASH_SALT` | A hashing salt for the case when a license needs to be disabled. Any random, but consistent value is fine. |

## Protocol

Relay clients communicate with the relay server using the following protocol. See [./src/bucketsrelay/proto.nim](./src/bucketsrelay/proto.nim) for more information, and [./src/bucketsrelay/stringproto.nim](./src/bucketsrelay/stringproto.nim) for encoding details.

In summary, devices connect with websockets and exchange messages. Messages sent from client to server are called commands. Messages sent from server to client are called events.

### Authentication

Clients authenticate with the server in two ways:

1. With a relay account via HTTP Basic authentication. This is used to group together a user's various clients and prevent abuse.
2. With a public/private key. This is used to identify and connect individual clients.

A single relay account can have multiple public/private keys; typically one for each device.

### Client Commands

Clients send the following commands:

| Command      | Description |
|--------------|-------------|
| `Iam`        | In response to a `Who` event, proves that this client has the private key for their public key. |
| `Connect`    | Asks the server for a connection to another client identified by the client's public key. |
| `Disconnect` | Asks the server to disconnect a connection to another client. |
| `SendData`   | Sends bytes to another client. |

### Server Events

The relay server sends the following events:

| Event           | Description |
|-----------------|-------------|
| `Who`           | Challenge for authenticating a client's public/private keys |
| `Authenticated` | Sent when a client successfully completes authentication |
| `Connected`     | Sent when a client has connected to another client |
| `Disconnected`  | Sent when a client has been disconnected from another client |
| `Data`          | Data payload from another, connected client |
| `Entered`       | Sent when a client within the same user account has authenticated to the relay |
| `Exited`        | Sent when a client within the same user account has disconnected from the relay |
| `ErrorEvent`    | Sent when errors happen with authentication, connection or message sending |

### Sequences and Usage

#### Authentication

Authentication happens like this:

1. On connection, server sends `Who(challenge=ABCD...)`
2. Client responds with `Iam(pubkey=MYPK..., signature=SIGN...)`
3. If the signature is correct, server sends `Authenticated`

```
Client           Relay
 │                 │
 │             Who │
 │◄────────────────┤
 │                 │
 │ Iam             │
 ├────────────────►│
 │                 │
 │  Authenticated  │
 │◄────────────────┤
 │                 │
```

#### Client-to-client connection

After authenticating, clients connect to each other and send data like this:

1. Alice sends `Connect(pubkey=BOBPK)`
2. Bob sends `Connect(pubkey=ALICEPK)`
3. Server sends Alice `Connected(pubkey=BOBPK)`
4. Server sends Bob `Connected(pubkey=ALICEPK)`
5. Alice sends data with `SendData(data=hello, pubkey=BOBPK)`
6. Server sends Bob data with `Data(data=hello, sender=ALICEPK)`

```
Alice             Relay              Bob
  │                 │                 │
  ├───Authenticated─┼─Authenticated───┤
  │                 │                 │
  │Connect(Bob)     │                 │
  ├────────────────►│ Connect(Alice)  │
  │                 │◄────────────────┤
  │                 │                 │
  │ Connected(Bob)  │ Connected(Alice)│
  │◄────────────────┼────────────────►│
  │                 │                 │
  │SendData(Bob)    │                 │
  ├────────────────►│ Data(Alice)     │
  │                 ├────────────────►│
  │                 │                 │
```

#### Same-user presence notifications

The relay server will announce client presence to all clients that use the same HTTP Auth credentials. For example, if both Alice and Bob signed in as `alicenbob@example.com` the following would happen:

1. Alice finishes authenticating
2. Bob finishes authenticating
3. Server sends Alice `Entered(pubkey=BOBPK)`
4. Server sends Bob `Entered(pubkey=ALICEPK)`
5. Alice disconnects
6. Server sends Bob `Exited(pubkey=ALICEPK)`


