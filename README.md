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
