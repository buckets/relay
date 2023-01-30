#!/bin/sh

waitForOpenPort() {

  PORT=$1
  HOSTTOCHECK="127.0.0.1"
  TIMEOUT=5
  echo "Waiting for $HOSTTOCHECK:$PORT to open"
  sleep "$TIMEOUT" &
  SLEEPPID=$!
  while ! nc -z "$HOSTTOCHECK" "$PORT"; do
    sleep 0.1
    if ! kill -0 "$SLEEPPID" 2>/dev/null; then
      echo "Timed out waiting for $HOSTTOCHECK:$PORT to open"
      return 1
    fi
  done
  kill "$SLEEPPID" 2>/dev/null
  echo "Port $HOSTTOCHECK:$PORT is open!"
  return 0
}

dotest() {
  echo "Adding a user ..."
  printf 'foobar' | brelay adduser me@me.com --password-stdin

  echo "Generating keys ..."
  (mkdir -p client1 && cd client1 && bclient genkeys)
  (mkdir -p client2 && cd client2 && bclient genkeys)
  echo "hello, world" > testfile

  echo "Starting the server ..."
  brelay server --port 8080 &
  CHILDPID=$!
  trap "kill $CHILDPID" exit

  waitForOpenPort 8080

  echo "Starting the clients ..."
  printf "hello, world" > client2/testfile
  (cd client1 && bclient receive -u me@me.com -p foobar http://127.0.0.1:8080/v1/relay "$(cat ../client2/relay.key.public)" > output) &
  CLIENT1PID=$!
  (cd client2 && cat testfile | bclient send -u me@me.com -p foobar http://127.0.0.1:8080/v1/relay "$(cat ../client1/relay.key.public)")
  wait $CLIENT1PID
  cat client1/output

  if [ "$(cat client2/testfile)" != "$(cat client1/output)" ]; then
    echo "input != output"
    exit 1
  fi

  echo "Showing some stats ..."
  echo '.timeout 1000' | sqlite3 buckets_relay.sqlite
  brelay stats
}

rm -r _tests
set -xe
mkdir -p _tests
(cd _tests && dotest)
