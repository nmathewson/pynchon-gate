#!/usr/bin/python
# Maas is Copyright 2011 by Nick Mathewson.                          ____/|/|
# This is free software; see LICENSE at end of file for more info.     O \|\|

from itertools import izip, count
import os
import mmap
import hashlib
import struct

HASH_LEN = 32

class DistFormatException(ValueError):
    pass

DFE = DistFormatException

def inOrder(seq):
    i = iter(seq)
    try:
        last = i.next()
    except StopIteration:
        return True
    for val in i:
        if last > val:
            return False
        last = val
    return True

def chunks(string, N):
    for p in xrange(0, len(string), N):
        yield string[p:p+N]

class Distribution:
    def __init__(self, metadata):
        self._parseMetadata(metadata)

    def getBucket(self, n):
        raise NotImplemented()

    def getNBuckets(self):
        raise NotImplemented()

    def _parseMetadata(self, m):
        m_orig = m
        if len(m) < 8 + HASH_LEN*6 + 4:
            raise DFE("Metadata way too short")

        self.ver, self.bs = struct.unpack("!LL", m[:8])
        if self.ver != 0:
            raise DFE("Version %s was unexpected"%ver)

        if (self.bs % 32) != 0:
            raise DFE("Block size %s was not a multiple of 32"%bs)

        self.ns_name    = m[8+HASH_LEN*0:8+HASH_LEN*2]
        self.ns_ident   = m[8+HASH_LEN*2:8+HASH_LEN*3]
        self.fname      = m[8+HASH_LEN*3:8+HASH_LEN*5]
        self.dst_digest = m[8+HASH_LEN*5:8+HASH_LEN*6]
        midx_nents,      = struct.unpack("!L", m[8+HASH_LEN*6:8+HASH_LEN*6+4])

        m = m[8+HASH_LEN*6+4:]
        if len(m) < HASH_LEN*(2*midx_nents) + 4:
            raise DFE("Metaindex truncated: didn't have room for %d entries"%midx_nents)

        self.metaindex = []
        for i in xrange(midx_nents):
            entry = m[i*(HASH_LEN*2):(i+1)*(HASH_LEN*2)]
            first_uid  = entry[:HASH_LEN]
            idx_digest = entry[HASH_LEN:]
            self.metaindex.append( (first_uid, idx_digest) )

        m = m[midx_nents*(HASH_LEN*2):]
        siglen, = struct.unpack("!L", m[:4])
        if len(m) < siglen + 4:
            raise DFE("Metaindex truncated in the signature.")
        elif len(m) > siglen + 4:
            raise DFE("Extra junk at the end of the metaindex")

        self.msg_hash = hashlib.sha256(m_orig[:-len(m)]).digest()
        self.signature = m[4:]

    def checkSignature(self, pk):
        pass #XXXX

    def checkMetaindex(self):
        for i, (first_uid, bucket_digest) in izip(count(), self.metaindex):
            b = self.getBucket(i)
            if hashlib.sha256(b).digest() != bucket_digest:
                raise DFE("Metaindex has the wrong hash for idx bucket %d"%i)
            if b[:HASH_LEN] != first_uid:
                raise DFE("Metaindex has has the wrong first-uid for idx bucket %d"%i)

        if not inOrder(first_uid for first_uid, _ in self.metaindex):
            raise DFE("Metaindex first_uid values are not in ascending order")

    def checkIndex(self):
        users = []
        userbuckets = []
        for i in xrange(len(self.metaindex)):
            b = self.getBucket(i)
            users = users[:-1]
            userbuckets = userbuckets[:-1]
            for entno, entry in izip(count(), chunks(b, HASH_LEN*2+8)):
                if len(entry) < HASH_LEN*2+8:
                    if entry != "\x00"*len(entry):
                        raise DFE("index block %d was not 00-padded."%i)

                userid = entry[:HASH_LEN]
                bucketnum, bucketpos = struct.unpack("!LL", entry[HASH_LEN:HASH_LEN+8])
                buckethash = entry[HASH_LEN+8:]
                if userid == "\x00"*HASH_LEN:
                    if any(byte != '\x00' for byte in b[entno*(HASH_LEN*2+8)]):
                        raise DFE("Null userid did not preceed an all-zero block ending")
                    if i != len(self.metaindex)-1:
                        raise DFE("Null userid occurred outside of last block")
                    break

                users.append(userid)
                userbuckets.append(bucketnum)
                msgbucket = self.getBucket(bucketnum)
                if hashlib.sha256(msgbucket).digest() != buckethash:
                    raise DFE("Bad hash for entry %d in idx bucket %d"%(entno, i))
                if bucketnum < len(self.metaindex):
                    raise DFE("Index pointed back into itself for entry %d in bucket %d"%(entno,i))

            if not inOrder(users):
                raise DFE("UserIDs not sorted in bucket %d"%i)
            if not inOrder(userbuckets):
                raise DFE("Bucket numbers not sorted in bucket %d"%i)

    def checkUserBucketChain(self):
        n = self.getNBuckets()
        lastHash = None
        for i in xrange(len(self.metaindex), n):
            b = self.getBucket(i)
            if lastHash != None and hashlib.sha256(b).digest() != lastHash:
                raise DFE("Wrong hash chain value for bucket %d"%i)
            lastHash = b[:HASH_LEN]
        if lastHash != '\x00'*HASH_LEN:
            raise DFE("Hash chain value in last user bucket was not 0")

    def checkAll(self):
        if (self._size % self.bs) != 0:
            raise DFE("The file looks truncated: it isn't a round number of buckets")
        self.checkMetaindex()
        self.checkIndex()
        self.checkUserBucketChain()

class MappedDistribution(Distribution):
    def __init__(self, metadata_fname, data_fname):
        Distribution.__init__(self, open(metadata_fname).read())

        self._fd = os.open(data_fname, os.O_RDONLY)
        self._size = os.fstat(self._fd).st_size
        self._map = mmap.mmap(self._fd, self._size, mmap.MAP_PRIVATE)

    def getNBuckets(self):
        return self._size // self.bs

    def getBucket(self, i):
        return self._map[self.bs * i : self.bs * (i+1)]


class ScannedDistribution(Distribution):
    def __init__(self, metadata_fname, data_fname):
        Distribution.__init__(self, open(metadata_fname).read())

        self._fd = os.open(data_fname, os.O_RDONLY)
        self._size = os.fstat(self._fd).st_size

    def getNBuckets(self):
        return self._size // self.bs

    def getBucket(self, i):
        os.lseek(self._fd, self.bs * i, 0)
        v = os.read(self._fd, self.bs)
        assert len(v) == self.bs
        return v

if __name__ == '__main__':
    import sys
    D = MappedDistribution(sys.argv[1], sys.argv[2])
    D.checkAll()
    print "Looks ok to me"
