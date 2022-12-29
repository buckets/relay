This repository contains the open source code for the [Buckets](https://www.budgetwithbuckets.com) relay server, which allows users to share budget data between their devices in an end-to-end encrypted way.

## Quickstart

If you want to run the relay on your own computer, do the following:

1. Install [Nim](https://nim-lang.org/)
2. Run `nimble install https://github.com/buckets/relay.git`
3. Add a user with `brelay adduser myusername`
4. Run the server with `brelay server`

This will launch the relay on the default port. Run `brelay --help` for more options.

TODO: include instructions for securing with TLS

## Security

- You should ensure that connections to this relay server are made with TLS.
- This relay server can see all traffic, so clients should encrypt data intended for other clients.
- Clients should also authenticate each other through the relay and not trust the authentication done by this server.

## Development

To run the server locally:

  nimble run brelay server
