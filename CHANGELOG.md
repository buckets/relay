# v0.2.0 - 2023-02-07

- **NEW:** Add docker build testing to CI
- **NEW:** Enable using TLS without needing another server in front.
- **NEW:** Relay remembers `Connect` requests even after remote disconnects.
- **FIX:** Fixed cleanup of connections so that nothing attempts to write to closedd streams
- **FIX:** Make RelayClient.handler public
- **FIX:** Prevent attackers from preemptively setting passwords on accounts that authenticate with licenses.
- **FIX:** Update to version of websock that includes the memory fix
- **FIX:** Only keep stats for 90 days ([#6](https://github.com/buckets/relay/issues/6))
- **FIX:** Fix nimble package so that library is importable as `bucketsrelay`.
- **FIX:** Fix race condition in functional test ([#5](https://github.com/buckets/relay/issues/5))
- **FIX:** Fix excessive memory use per websocket connection. Now ~20k instead of 1MB

# v0.1.0 - 2023-01-24

- **NEW:** Initial release

