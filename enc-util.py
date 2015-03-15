#!/usr/bin/python

import sys
import struct
import libnacl
import libnacl.utils
import simpleubjson

structformat = "!HH"

# This will encrypt a file given to stdin onto stdout. The first argument is the public key file to encrypt to.

pkey = libnacl.utils.load_key(sys.argv[1])

COUNTER_BYTES = 5

sym_key = libnacl.utils.salsa_key()
nonce_bytes = libnacl.randombytes(libnacl.crypto_box_NONCEBYTES - COUNTER_BYTES)
block_size = 512
# Will need to store both the key and the nonce

sign_key = libnacl.public.SecretKey()

mapbytes = lambda x: [int(i) for i in x]

securemetadata = {
    "key": mapbytes(sym_key),
    "nonce_bytes": mapbytes(nonce_bytes),
    "block_size": block_size,
}
binarysecuremetadata = simpleubjson.encode(securemetadata)
smdbox = libnacl.public.Box(sign_key.sk, pkey.pk)
encryptedsecuremetadata = smdbox.encrypt(binarysecuremetadata)

metadata = {
    "algorithm": "curve25519-salsa20-vblock",
    "sign_key": mapbytes(sign_key.pk),
    "secure": mapbytes(encryptedsecuremetadata),
}

encodedmetadata = simpleubjson.encode(metadata)

metalength = len(encodedmetadata)

magicbytes = b'BR'
version = 2

sys.stdout.buffer.write(magicbytes)

firstbytes = struct.pack(structformat, version, metalength)

sys.stdout.buffer.write(firstbytes)

sys.stdout.buffer.write(encodedmetadata)

def encrypt(data, stdout):
    counter = 0
    block = data.read(block_size)
    while len(block) > 0:
        #if (counter.bit_length() > 8 * COUNTER_BYTES):
        #    return
        counter_bytes = counter.to_bytes(COUNTER_BYTES, "big")
        
        nonce = nonce_bytes + counter_bytes
        
        eblock = libnacl.crypto_stream_xor(block, nonce, sym_key)
        #yield eblock
        stdout.write(eblock)
        block = data.read(block_size)

#for i in encrypt(sys.stdin.buffer):
#    sys.stdout.buffer.write(i)

encrypt(sys.stdin.buffer, sys.stdout.buffer)

        
    
    
