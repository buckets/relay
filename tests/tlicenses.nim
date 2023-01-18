import std/strutils
import std/unittest

import relay/licenses

const PRIVATEKEY1 = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAkFVXBWA85bBdFOpdwusXL5hELbGh9u7cg/ZeoV1ToDD02Tw2
BEetGBUSzXsp3fKPbx89wigTjGAJNHAXVGcdbAbBCve+ARhTJTHIrXZ3lXNxvl0j
KfXNa0VqV79WPeZaRtlvC0e8G9A8sL1wjvZn0nL2DG3gGBLeyAeSYiSCE8ROx5op
oDylJRj5RVTWDtCsQFU4j5h7+Jk2nFCfIsaLyDDKquiycIRcXAt8f32RaMEZn0qh
OXnqjHRAEF8V8hvDVfvVwx4iJXcAdnbDHKIl/aD7ssk2fYqeh0kFRH0zyLmPgFoJ
UYOb+opA1NsWBcZCmaeyLC+RWjJDDXQW9H4NgwIDAQABAoIBACEBkwvkrShtg2vE
CLsJXd0Beh3k8D/y8bSvw4YtPHF2oJeJAGVMKtZGA23AC5v42zozL8FVvtqsH47B
T2R6zCynAsBKVUYU1Pa9gsHARKqFou5AiEkRL++nCSGV3Nf89IodMRqoRekqXqag
O7xFtwpWRdQj0EpRDmc57AzLgn+YWrdhwy/2IklJpkmbXiE/lr2Hmgt1eLPb+F5Q
zJ3JGpLKyFmgQZEuShhSVFJnqnFdJGhpK6DDI9XTEufxoBOhEbgJyJrc3FKqjQ4s
Fro4GGNBOjFzOM8nAVWjAeMTMDh/6DSFDP0DDhbQlCHvKfv78UK7oIDEylGOwSha
ODaTVWECgYEA+6gRIR5M9hy8E4/09ZwWjCgOqOSEEL4dluZWSS8a3nMLLTz/Q18u
disfJVNP/rFPO40eRP5FdNHXtXDVbOFclCm0tERcWzQNFYNi54vT9yGQrMpdqJsd
a5/vX3vztvr0Kw7O3jPwzCOkMne04BGZKW/TJelguEBN6d0wNNYh1dMCgYEAktMS
CLM+tyf/tULVAkapYr6kr/fi5ZyNn7S6YkZQx8soH54JfhMqbBCzRwSeF2NKnj7D
XBzjp4FFQoFCoqNwo0G9nTAoOoY6y3S9lLTZr4LjTthW4Zgo1JpgD6/jIEL/v2mC
zpEpvfUWWKjVCn77QBj9Zxoda9v0DRa40DiAq5ECgYEAvXsJEree2Pw/vDb7COcy
rusGRrJwoa6T1uetdkMKZw2WD8TKqi6DbCQBunflVm6oqr0RWn9dSp0pXosLl4SD
0WcpkUWbiGxDobwgfxjwSzYxmXhxVp8cYsm0UV+h3FdN+xGWPwY6u2nmmr05KjD1
8pYpFHWJBpIcWAbb4hyMs1MCgYA0tnTODNRiW4jxocnp5Eah/gIQbzXV68vo37De
4ZHU+Toxh8KuseDUJXbH839ytCIxCCWJZ5HQLJgaFWBAFd+1rT+PNJ/syw5Gx2Xd
AsT4v0wunXsryT43fiko2KP5jDRXm2DsGq/a1CgusoayGv7Hd3Fa18RiWfiXzmWR
1AdWEQKBgQCGjvSH/6cVzf5L8qpdhGcZ1jIalc5K0eO5//qvCYv8HysdXB8mUfdh
63oK3QONPrYql3KKLgWjQxaffPEWshm4c02tuJQanSGa2yTQwhSJsk4hg1iY+7lX
ihlOePC/fSmBJCmr9f0n0DNn1MxUL6GuIU7peFGm5Q1TJ0toimWG/w==
-----END RSA PRIVATE KEY-----
""".strip()

const PUBLICKEY1 = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkFVXBWA85bBdFOpdwusX
L5hELbGh9u7cg/ZeoV1ToDD02Tw2BEetGBUSzXsp3fKPbx89wigTjGAJNHAXVGcd
bAbBCve+ARhTJTHIrXZ3lXNxvl0jKfXNa0VqV79WPeZaRtlvC0e8G9A8sL1wjvZn
0nL2DG3gGBLeyAeSYiSCE8ROx5opoDylJRj5RVTWDtCsQFU4j5h7+Jk2nFCfIsaL
yDDKquiycIRcXAt8f32RaMEZn0qhOXnqjHRAEF8V8hvDVfvVwx4iJXcAdnbDHKIl
/aD7ssk2fYqeh0kFRH0zyLmPgFoJUYOb+opA1NsWBcZCmaeyLC+RWjJDDXQW9H4N
gwIDAQAB
-----END PUBLIC KEY-----
""".strip()

const PRIVATEKEY2 = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDCqQMftQvDX2B2oJl1t7eXRSMhviklJx00olcqI/4okB2WLX18
3wNUM+O+DZiMAkOlMk96Z6y1Rs03CmV4wJmu4fwrOGFrcS1nsOky8z9KLPENmzxp
0FAL2xwdG6TEhGOlHSRloDQQN58CEjegPYGcLwiysL30fmK69GbVE6f1ZwIDAQAB
AoGBAJCtVzIIuH5z89kXUhdo/V3Dt/HLSP9hC9bj1Y7vg2YYfrTwiHT3t5ysmFbX
+goNYMN2GhYq2fU9cya2ZmaSF2XR9fD5zGINSFltSSOQTUtokhUUx6pVDk06CmjJ
vetu7//nhVp1xP4T2IHXIOuaOB1FxfMlUk8LV+TNsmhsXHgxAkEA/WbYpDp8ukLw
ryhpOaqZiZW06aTe8seLNS2U7cGlTe+VsA9uGwS1HHIvAiOQ9/4f5rjM3XZtNwZD
NrH+2BambwJBAMSn+bNuoFUtwVGzKSaAMGOg/IERQN8uH73iSCSaFnfM7Kwzl4o7
u96nEYi0B2R7UMa/UwbgpBDplnvZ8QRXXIkCPw/WXbPl8+WwSVqpK+puvynaMXRo
2YZS8mBgeO5jK/GzB6f5TuhhYvBkMovvrR/SwiupYSR2Ql0uBwVkGolm4QJANFHs
YQyho4fU0wOzgwa/2QHPrBcHB1miIEa/ot1L9PuUTAw92Q0jYo1YYOJkxRr51qa4
VDAX9lfvLWxCb0E+4QJBAJlhxvujrPotY6/rXMVAY6Zt+MmQiUiYNDVm4eEaH6t5
jMiVvR+d8aAzTRTV1U8jg+LwhM7t0lyN5gIC8NeuHuU=
-----END RSA PRIVATE KEY-----
""".strip()

const PUBLICKEY2 {.used.} = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCqQMftQvDX2B2oJl1t7eXRSMh
viklJx00olcqI/4okB2WLX183wNUM+O+DZiMAkOlMk96Z6y1Rs03CmV4wJmu4fwr
OGFrcS1nsOky8z9KLPENmzxp0FAL2xwdG6TEhGOlHSRloDQQN58CEjegPYGcLwiy
sL30fmK69GbVE6f1ZwIDAQAB
-----END PUBLIC KEY-----
""".strip()

suite "BucketsV1RSALicense":

  test "works":
    let license = createV1License(PRIVATEKEY1, "foo@foo.com")
    check $license is string
    checkpoint $license
    check verify(license, PUBLICKEY1) == true
    check extractEmail(license) == "foo@foo.com"    

  test "wrong key":
    let license = createV1License(PRIVATEKEY2, "bad@foo.com")
    check $license is string
    checkpoint $license
    check verify(license, PUBLICKEY1) == false
    check extractEmail(license) == "bad@foo.com"
