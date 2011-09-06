#!/usr/bin/python

#
# Make a 49-block file of 64-byte blocks.
#

with open('distfile.bs64', 'w') as f:

    for n in xrange(49):
        block = "The crying of lot %s"%n
        block += "."*(64-len(block))
        f.write(block)

