
set -xe
rm brelay.sqlite || echo okay to fail

PORT=9000
nim c -o:/tmp/server2 src/server2.nim
nim c -o:/tmp/sampleclient src/sampleclient.nim
/tmp/server2 server &
SERVERPID="$!"
while ! nc -z 127.0.0.1 $PORT; do
  echo "Waiting for $PORT"
  sleep 1
done
/tmp/sampleclient tests
RC=$?
pkill -P "$SERVERPID"
exit "$RC"
