import std/unittest

import objs

suite "encode":
  test "nsencode":
    check nsencode("apple") == "5:apple,"
    check nsencode("") == "0:,"
    check nsencode("banana\x00,") == "8:banana\x00,,"

  test "nsencode newline allowed instead of comma":
    check nsencode("apple", '\n') == "5:apple\n"
    check nsencode("", '\n') == "0:\n"
    check nsencode("banana\x00\n", '\n') == "8:banana\x00\n\n"

suite "decode":

  test "basic":
    check nsdecode("5:apple,") == "apple"
  
  test "incomplete":
    expect(IncompleteNetstring):
      discard nsdecode("7:bana")
  
  test "2 strings":
    var idx = 0
    check nsdecode("5:apple,3:f\x00o,", idx) == "apple"
    check nsdecode("5:apple,3:f\x00o,", idx) == "f\x00o"
  
  test "newline delimiter":
    check nsdecode(nsencode("apple", '\n')) == "apple"

  test "empty string":
    check nsdecode("0:,") == ""
  
  test "can't start with 0":
    expect(NetstringError):
      discard nsdecode("01:a,")
  
  test "can't include non-numerics":
    expect(NetstringError):
      discard nsdecode("1a:,")
  
  test ": required":
    expect(NetstringError):
      discard nsdecode("1f,")
  
  test ", required":
    expect(NetstringError):
      discard nsdecode("1:a2:ab,")
  
  test "len required":
    expect(NetstringError):
      discard nsdecode(":s,")

  test "max message length":
    check nsdecode("4:boom,", maxlen=4) == "boom"
    expect(NetstringError):
      discard nsdecode("5:apple,", maxlen=4)
    expect(NetstringError):
      discard nsdecode("200:a", maxlen=100)
