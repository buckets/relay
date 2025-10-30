#!/bin/bash

RC=0
FAILED=
PASSED=
for filename in $(ls tests/t*.nim); do
  echo $filename
  nim r "$filename"
  rc1=$?
  if [ ! "$rc1" == "0" ]; then
    RC="$rc1"
    FAILED="$filename $FAILED"
  else
    PASSED="$filename $PASSED"
  fi
done

for filename in $PASSED; do
  echo "PASSED: $filename"
done
for filename in $FAILED; do
  echo "FAILED: $filename"
done

if [ "$RC" == "0" ]; then
  echo "OK"
else
  echo "exit=$RC"
fi

exit "$RC"
