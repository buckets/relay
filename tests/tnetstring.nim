import std/unittest

import bucketsrelay/netstring

test "nsencode":
  check nsencode("apple") == "5:apple,"
  check nsencode("") == "0:,"
  check nsencode("banana\x00,") == "8:banana\x00,,"

test "nsencode newline allowed instead of comma":
  check nsencode("apple", '\n') == "5:apple\n"
  check nsencode("", '\n') == "0:\n"
  check nsencode("banana\x00\n", '\n') == "8:banana\x00\n\n"

suite "NetstringDecoder":

  test "netstring in, message out":
    var ns = newNetstringDecoder()
    ns.consume("5:apple,")
    check ns.len == 1
    ns.consume("7:bana")
    check ns.len == 1
    ns.consume("na\x00,3:foo,3:bar")
    check ns.len == 3
    ns.consume(",")
    check ns.len == 4
    check ns.nextMessage() == "apple"
    check ns.nextMessage() == "banana\x00"
    check ns.nextMessage() == "foo"
    check ns.nextMessage() == "bar"
  
  test "newline delimiter":
    var ns = newNetstringDecoder('\n')
    ns.consume("5:apple\n")
    check ns.len == 1
    ns.consume("7:bana")
    check ns.len == 1
    ns.consume("na\x00\n3:foo\n3:bar")
    check ns.len == 3
    ns.consume("\n")
    check ns.len == 4
    check ns.nextMessage() == "apple"
    check ns.nextMessage() == "banana\x00"
    check ns.nextMessage() == "foo"
    check ns.nextMessage() == "bar"

  test "empty string":
    var ns = newNetstringDecoder()
    ns.consume("0:,")
    check ns.nextMessage() == ""
  
  test "can't start with 0":
    var ns = newNetstringDecoder()
    expect(Exception):
      ns.consume("01:,")
  
  test "can't include non-numerics":
    var ns = newNetstringDecoder()
    expect(Exception):
      ns.consume("1a:,")
  
  test ": required":
    var ns = newNetstringDecoder()
    expect(Exception):
      ns.consume("1f,")
  
  test ", required":
    var ns = newNetstringDecoder()
    expect(Exception):
      ns.consume("1:a2:ab,")
  
  test "len required":
    var ns = newNetstringDecoder()
    expect(Exception):
      ns.consume(":s,")

  test "max message length":
    var ns = newNetstringDecoder()
    
    ns.maxlen = 4
    ns.consume("4:fooa,")
    expect(Exception):
      ns.consume("5:")
    ns.reset()

    ns.maxlen = 10000
    expect(Exception):
      ns.consume("100000")
