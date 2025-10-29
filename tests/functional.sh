
set -x
rm brelay.sqlite

PORT=9000
nim c -o:/tmp/server2 src/server2.nim
/tmp/server2 server &
SERVERPID="$!"
while ! nc -z 127.0.0.1 $PORT; do
  echo "Waiting for $PORT"
  sleep 1
done
nim r src/sampleclient.nim publishnote topic1 value1
nim r src/sampleclient.nim publishnote topic1 value1 || echo failed on purpose
RC=$?


pkill -P "$SERVERPID"
exit "$RC"
