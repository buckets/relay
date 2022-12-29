# Copyright (c) 2022 One Part Rain, LLC. All rights reserved.
#
# This work is licensed under the terms of the MIT license.  
# For a copy, see LICENSE.md in this repository.

import std/unittest
import std/strutils
import ./util

import chronos

import relay/server

test "add user":
  withinTmpDir:
    var rs = newRelayServer("test.db")
    let uid = rs.register_user("foo", "password")
    check rs.is_email_verified(uid) == false
    check rs.can_use_relay(uid) == false
    check rs.password_auth("foo", "password") == uid
    expect WrongPassword:
      discard rs.password_auth("foo", "something else")

    let token = rs.generate_email_verification_token(uid)
    checkpoint "token: " & token
    check rs.use_email_verification_token(uid, token) == true
    check rs.is_email_verified(uid) == true
    check rs.can_use_relay(uid) == true

test "duplicate users not allowed":
  withinTmpDir:
    var rs = newRelayServer("test.db")
    discard rs.register_user("foo", "password")
    expect DuplicateUser:
      discard rs.register_user("foo", "another")

test "email verification only 5 latest codes work":
  withinTmpDir:
    var rs = newRelayServer("test.db")
    let uid = rs.register_user("foo", "password")
    let t1 = rs.generate_email_verification_token(uid)
    discard rs.generate_email_verification_token(uid)
    let t3 = rs.generate_email_verification_token(uid)
    discard rs.generate_email_verification_token(uid)
    check rs.use_email_verification_token(uid, "invalid token") == false
    check rs.is_email_verified(uid) == false

    check rs.use_email_verification_token(uid, t1) == false # failed because only 5 are valid
    check rs.is_email_verified(uid) == false

    check rs.use_email_verification_token(uid, t3) == true
    check rs.is_email_verified(uid) == true

proc verified_user(rs: RelayServer, email: string, password = ""): int64 =
  result = rs.register_user(email, password)
  let token = rs.generate_email_verification_token(result)
  assert rs.use_email_verification_token(result, token) == true

test "reset password":
  withinTmpDir:
    var rs = newRelayServer(":memory:")
    let uid = rs.register_user("foo", "password")
    let t1 = rs.generate_password_reset_token("foo")
    check rs.user_for_password_reset_token(t1).get() == uid
    rs.update_password_with_token(t1, "newpassword")
    check rs.password_auth("foo", "newpassword") == uid

test "reset password once only":
  withinTmpDir:
    var rs = newRelayServer(":memory:")
    let uid = rs.register_user("foo", "password")
    let t1 = rs.generate_password_reset_token("foo")
    check rs.user_for_password_reset_token(t1).get() == uid
    rs.update_password_with_token(t1, "newpassword")
    expect NotFound:
      rs.update_password_with_token(t1, "another password")
    check rs.password_auth("foo", "newpassword") == uid

test "block user":
  withinTmpDir:
    var rs = newRelayServer("test.db")
    var uid = rs.verified_user("foo")
    var other = rs.verified_user("bar")
    rs.block_user("foo")
    check rs.can_use_relay(uid) == false
    check rs.can_use_relay(other) == true
    rs.unblock_user("foo")
    check rs.can_use_relay(uid) == true
    check rs.can_use_relay(other) == true

test "log user data":
  withinTmpDir:
    var rs = newRelayServer("test.db")
    var uid = rs.verified_user("foo")
    rs.log_user_data_sent(uid, 10)
    rs.log_user_data_recv(uid, 20)
    rs.log_user_data_sent(uid, 30)
    rs.log_user_data_recv(uid, 40)
    check rs.data_by_user(uid, days = 1) == (40, 60)
    rs.log_ip_data_sent("10.0.0.5", 10)
    rs.log_ip_data_recv("10.0.0.4", 20)
    check rs.data_by_ip("10.0.0.5", days = 1) == (10, 0)
    check rs.data_by_ip("10.0.0.4", days = 1) == (0, 20)

    check rs.top_data_users(10, days = 7) == @[
      ("foo", (40, 60)),
    ]
    check rs.top_data_ips(10, days = 7) == @[
      ("10.0.0.4", (0, 20)),
      ("10.0.0.5", (10, 0)),
    ]
