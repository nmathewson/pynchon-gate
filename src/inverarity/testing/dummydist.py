#!/usr/bin/python

#
# Make a 49-block file of 64-byte blocks.
#

with open('distfile.bs64', 'w') as f:

    for n in xrange(49):
        block = "The crying of lot %s"%n
        block += "."*(64-len(block))
        f.write(block)

with open('distfile.meta', 'w') as f:
    f.write("\x00"*4) #version
    f.write("\x00\x00\x00\x40") # bucket size
    f.write("demonstration nymserver                                         ")
    f.write("\x11"*32) # nymserver ID. Won't validate.
    f.write("demonstration dist                                              ")
    f.write("\x22"*32) # distribution ID. Won't validate.
