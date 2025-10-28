#!/bin/bash

RC=0
for filename in $(ls tests/t*.nim); do
  echo $filename
  nim r "$filename"
  rc1=$?
  if [ ! "$rc1" == "0" ]; then
    RC="$rc1"
  fi
done

exit "$RC"
