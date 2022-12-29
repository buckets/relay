This repository contains the open source code for the [Buckets](https://www.budgetwithbuckets.com) relay server, which allows users to share budget data between their devices in an end-to-end encrypted way.

# Quickstart

If you want to run the relay on your own computer, do the following:

1. Install [Nim](https://nim-lang.org/)
2. Run `nimble install https://github.com/buckets/relay.git`
3. Add a user with `brelay adduser myusername`
4. Run the server with `brelay server`

This will launch the relay on the default port. Run `brelay --help` for more options.

## Registration

Compiled with default configuration, the relay server does not allow for users to register and will log emails rather than sending them. Register users via `brelay adduser ...`

To enable user registration and mailing:

1. Compile with `-d:openregistration`
2. Compile with `-d:usepostmark` to enable emailing via [Postmark](https://postmarkapp.com/)
3. Run with `POSTMARK_API_KEY=` set to your Postmark API key, or else embed the key in the executable with `-d:POSTMARK_API_KEY=embed:YOURPOSTMARKKEY`
4. Compile with `-d:release`

A complete example:

```
nimble install https://github.com/buckets/relay.git -d:openregistration -d:usepostmark -d:release
POSTMARK_API_KEY="foobar" brelay server
```

## TLS

TODO: include instructions for securing with TLS

# Security

- You should ensure that connections to this relay server are made with TLS.
- This relay server can see all traffic, so clients should encrypt data intended for other clients.
- Clients should also authenticate each other through the relay and not trust the authentication done by this server.

# Development

To run the server locally:

  nimble run brelay server
