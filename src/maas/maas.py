#!/usr/bin/python
# Maas is Copyright 2011 by Nick Mathewson.                          ____/|/|
# This is free software; see LICENSE at end of file for more info.     O \|\|

import os
import hashlib
import binascii
import struct
import M2Crypto.RSA as RSA
import M2Crypto.BIO as BIO
from cStringIO import StringIO

# Package a pile of data, identified by user-id, into a distribution
# plus metadata.

# Input: A directory containing a bunch of files, each of whose name
# is a hexadecimal userID.  Anything that isn't a hex userid gets
# hashed with sha256 and turned into one.
#
# Also required is a key for signing the metaindex.

# Output: A file and a metaindex file, as specified in spec.txt.

BUCKET_SIZE = 8*1024

HASH_LEN = 32
IDX_ENT_LEN = HASH_LEN * 2 + 4 + 4

def ceilDiv(a,b):
    return (a + b - 1) // b

def fmt_u32(v):
    return struct.pack("!L", v)

def zero_pad(s, n):
    if len(s) > n:
        return s[:n]
    else:
        return s+"\x00"*n

def get_public_key_digest(key):
    bio = BIO.MemoryBuffer()
    pub = RSA.new_pub_key(key.pub())
    pub.save_key_der_bio(bio)
    asn1 = bio.read()
    bio.close()
    return hashlib.sha256(asn1).digest()

class Distribution:
    def __init__(self, directory):
        self._dir = directory

        self._files = [ ] # (filename, userid[binary], size, nBuckets)
        self._user_buckets = 0

        self._key = None
        self._my_name = ""
        self._my_id = "\x00"*HASH_LEN

    def setIdentity(self, my_name, private_key):
        self._my_name = my_name
        self._key = private_key
        self._my_id = get_public_key_digest(private_key)

    def scanDirectory(self):
        total_user_buckets = 0

        for fn in os.listdir(self._dir):
            if fn.startswith("."):
                continue

            userid = None
            if len(fn) == HASH_LEN*2:
                try:
                    userid = binascii.a2b_hex(fn)
                except TypeError:
                    pass
            if userid == None:
                userid = hashlib.sha256(fn).digest()

            size = os.stat(os.path.join(self._dir,fn)).st_size
            n_buckets = ceilDiv(size, BUCKET_SIZE - HASH_LEN)

            self._files.append((userid, fn, size, n_buckets))
            total_user_buckets += n_buckets

        self._files.sort()
        self._user_buckets = total_user_buckets

    def writeDistribution(self, outFname):
        idx_ents_per_bucket = ceilDiv(BUCKET_SIZE, IDX_ENT_LEN)
        idx_buckets = ceilDiv(len(self._files), idx_ents_per_bucket)
        user_buckets = self._user_buckets

        f_output = open(outFname+".bs%s"%BUCKET_SIZE, 'wb')

        # This will NOT make for the nicest IO pattern in the whole world.
        f_output.seek((user_buckets+idx_buckets-1)*BUCKET_SIZE)

        # Perhaps we should flush these periodically?
        index_entries = [ ] # (userid, bucket-idx, pos within bucket, digest)

        last_digest = "\x00"*HASH_LEN

        file_stride = BUCKET_SIZE - HASH_LEN
        buckets_written = 0

        for userid, fn, size, n_buckets in reversed(self._files):
            with open(os.path.join(self._dir, fn), 'rb') as f_input:
                for user_bucketnum in xrange(n_buckets-1, -1, -1):
                    d = hashlib.sha256(last_digest)
                    f_input.seek(user_bucketnum*file_stride, 0)
                    f_output.write(last_digest)
                    content = f_input.read(file_stride)
                    if len(content) < file_stride:
                        content += "\x00" * (file_stride - len(content))
                    f_output.write(content)
                    f_output.seek(-BUCKET_SIZE*2, 1)
                    d.update(content)
                    last_digest = d.digest()
                    buckets_written += 1

            user_bucket_idx = user_buckets + idx_buckets - buckets_written

            index_entries.append((userid, user_bucket_idx, 0, last_digest))

        # Okay.  Now we need to build the index blocks.  This, we can do
        # forwards.
        index_entries.reverse()
        f_output.seek(0)
        idx_block_num = 0
        metaindex_entries = [ ] # (first userid, hash of idx block)

        for block_start in xrange(0, len(index_entries), idx_ents_per_bucket):
            d = hashlib.sha256()
            for userid, user_bucket_idx, offset, bucket_digest in \
                    index_entries[block_start:block_start+idx_ents_per_bucket]:
                entry = "%s%s%s%s"%(userid,
                                    fmt_u32(user_bucket_idx),
                                    fmt_u32(offset),
                                    bucket_digest)
                assert len(entry) == IDX_ENT_LEN
                d.update(entry)
                f_output.write(entry)
            f_output_pos = f_output.tell()
            assert f_output_pos == (idx_block_num * BUCKET_SIZE +
                                    IDX_ENT_LEN * len(index_entries[block_start:block_start+idx_ents_per_bucket]))
            if f_output_pos < (idx_block_num+1)*BUCKET_SIZE:
                padding = "\x00"*((idx_block_num+1)*BUCKET_SIZE - f_output_pos)
                f_output.write(padding)
                d.update(padding)

            first_userid = index_entries[block_start][0]
            idx_block_digest = d.digest()
            metaindex_entries.append((first_userid, idx_block_digest))

        f_output.close()

        d = hashlib.sha256()
        with open(outFname+".bs%s"%BUCKET_SIZE, 'rb') as f:
            s = f.read(BUCKET_SIZE)
            d.update(s)
        distribution_digest = d.digest()

        d = hashlib.sha256()
        f_meta = open(outFname+".meta", 'wb')
        # Version: 4 bytes
        # Bucket size: 4 bytes.
        # Nymserver name: HASH_LEN*2 bytes.
        # Nymserver identity: HASH_LEN bytes.
        # File name: HASH_LEN*2 bytes.
        # Distribution digest: HASH_LEN bytes
        # Number of entries in the metaindex==MLEN: 4 bytes
        # Metaindex: MLen * (HASH_LEN*2) bytes
        # SigLen: 4 bytes
        # Signature: SigLen bytes
        meta_hdr_parts = [ fmt_u32(0),
                           fmt_u32(BUCKET_SIZE),
                           zero_pad(self._my_name, HASH_LEN*2),
                           self._my_id,
                           zero_pad(outFname, HASH_LEN*2),
                           distribution_digest,
                           fmt_u32(len(metaindex_entries)) ]
        meta_hdr = "".join(meta_hdr_parts)
        f_meta.write(meta_hdr)
        d.update(meta_hdr)
        for userid, idx_block_digest in metaindex_entries:
            formatted = userid + idx_block_digest
            f_meta.write(formatted)
            d.update(formatted)
        metainfo_digest = d.digest()

        # Last, try to sign this thing.
        if self._key == None:
            f_meta.write(fmt_u32(0))
            f_meta.close()
            return

        signature = self._key.sign_rsassa_pss(metainfo_digest, 'sha256', 32)
        f_meta.write(fmt_u32(len(signature)))
        f_meta.write(signature)
        f_meta.close()

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print """\
Syntax:
  maas.py KEY.pem directory
Outputs files in my-dist.bs8192, and my-dist.meta"""
        sys.exit(1)

    privkey = RSA.load_key(sys.argv[1])
    dist = Distribution(sys.argv[2])
    dist.scanDirectory()
    dist.setIdentity("maas-demo", privkey)
    dist.writeDistribution("my-dist")

## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to
## deal in the Software without restriction, including without limitation the
## rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
## sell copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
##
## The above copyright notice and this permission notice shall be included in
## all copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
## FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
## IN THE SOFTWARE.
