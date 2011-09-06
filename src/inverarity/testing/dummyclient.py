#!/usr/bin/python

import binascii
import socket
import ssl
import os
import struct
import hashlib

###### CONFIGURATION TO SET UP THE CLIENT
#
# In real life, we'll want this to be sent in from outside the library.
#
# This part configures whom we will talk to, and what we will ask for.


ID = "4DF18A15758CCC93F5A32DA9B898375A4CAA3FB8C9862784BDECBF678CF35426"

# A list of the distributors we should talk to.  We will make one request per
# distributor.  All of them must be running.
#
# Each distributor is represented by a 3-tuple of address, port, and hexadecimal
# certificate digest.
USE_HOSTS = [
    ( "127.0.0.1", 49494, ID),
    ( "127.0.0.1", 49494, ID),
    ( "127.0.0.1", 49494, ID),
    ( "127.0.0.1", 49494, ID),
    ( "127.0.0.1", 49494, ID),
]

# A hex sha256 digest of the distribution we're going to ask for part of
DIST_ID = "9be177fd1da8badbebe4a31e35c3e78e37f3c226f1af0f7ecaf3b5bb3ac083a1"

# Number of buckets in the distribution.
N_BUCKETS = 49
# Size of each bucket in the distribution.
BLOCK_SIZE = 64

def xor(a,b):
    assert len(a) == len(b)
    out = [ chr( ord(ac) ^ ord(bc) ) for ac,bc in zip(a,b) ]
    return out

def generate_bitfields(wanted, nBuckets=N_BUCKETS, nRequests=None):
    if nRequests == None:
        nRequests = len(USE_HOSTS)
    nBytes = (nBuckets+7) // 8
    result = []
    last_request = "\0"*nBytes
    for _ in xrange(nRequests - 1):
        r = os.urandom(nBytes)
        result.append(r)
        last_request = xor(last_request, r)
    whichbyte = wanted // 8
    whichbit = wanted % 8
    last_request[whichbyte] = chr( ord(last_request[whichbyte]) ^ (1<<whichbit) )
    result.append("".join(last_request))
    return result

def get_bit(bf, n):
    return ord(bf[n//8]) & (1<<(n & 7))

def connect(addr, port, identity):
    base_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = ssl.SSLSocket(base_s)
    s.connect((addr, port))
    # print "Connected to %s:%s"%(addr,port)

    if identity == None:
        print "   (No identity known for %s:%d)"%(addr,port)
    else:
        cert = s.getpeercert(binary_form=True)
        d = hashlib.sha256()
        d.update(cert)
        digest = d.digest()

        if digest != binascii.a2b_hex(identity):
            raise Error("Certificate for %s:%s was not as expected!" %(addr, port))

    return s

def fmt_u32(v):
    return struct.pack("!L", v)

def get_u32(s):
    return struct.unpack("!L", s)[0]

def recv_all(sock, n):
    total = 0
    result = []
    while total < n:
        s = sock.recv(n - total)
        result.append(s)
        total += len(s)
    return "".join(result)

def send_get(sock, bitfield, distid=DIST_ID):
    request_id = os.urandom(32)
    distid = binascii.a2b_hex(distid)

    req = (request_id + fmt_u32(0x1000) + fmt_u32(40+len(bitfield)) +
           distid + fmt_u32(N_BUCKETS) + fmt_u32(BLOCK_SIZE) )
    sock.send(req)
    sock.send(bitfield)

    rh = recv_all(sock, 32+8)
    if len(rh) != 40:
        print "oops, partial read", len(rh)
    id_match = True
    if request_id != rh[:32]:
        print "request id mismatch"
        id_match = False

    cmd_code = get_u32(rh[32:36])
    cmd_len = get_u32(rh[36:])

    if cmd_code == 0x2002:
        print "Got an error!"
    elif cmd_code == 0x2001:
        pass
    else:
        print "Got unknown command code %x??"%cmd_code

    cmd_body = recv_all(sock, cmd_len)
    if cmd_code == 0x2002:
        errcode = get_u32(cmd_body[:4])
        errlen = get_u32(cmd_body[4:8])
        err = cmd_body[8:8+errlen]
        print "Error was: %d: %s"%(errcode, err)
    elif id_match and cmd_code == 0x2001:
        datlen = get_u32(cmd_body[:4])
        data = cmd_body[4:4+datlen]
        if len(data) != datlen:
            print "Data length mismatch"
        return data

    return None


def fetch(wanted):
    bf = generate_bitfields(wanted)

    responses = []

    for (addr, port, identity), req in zip(USE_HOSTS, bf):
        s = connect(addr,port,identity)
        r = send_get(s, req)
        if r:
            responses.append(r)
        s.close()

    if len(responses) != len(bf):
        print "Not enough responses"
        return None

    result = "\0"*BLOCK_SIZE
    for resp in responses:
        result = xor(result, resp)

    return "".join(result)

print repr(fetch(12))

