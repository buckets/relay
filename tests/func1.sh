#!/bin/sh

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

  echo "Starting the clients ..."
  printf "hello, world" > client2/testfile
  (cd client1 && bclient receive -u me@me.com -p foobar http://127.0.0.1:8080 "$(cat ../client2/relay.key.public)" > output) &
  (cd client2 && cat testfile | bclient send -u me@me.com -p foobar http://127.0.0.1:8080 "$(cat ../client1/relay.key.public)")
  cat client1/output

  if [ "$(cat client2/testfile)" != "$(cat client1/output)" ]; then
    echo "input != output"
    exit 1
  fi

  echo "Showing some stats ..."
  brelay stats
}

rm -r _tests
set -xe
mkdir -p _tests
(cd _tests && dotest)
