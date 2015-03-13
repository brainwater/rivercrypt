import sys
import struct
import array
import libnacl
import libnacl.utils
import libnacl.public
import simpleubjson

fbformat = "!HH"

# Used for decrypting files encrypted with enc-util
#COUNTER_BYTES = 5

skey = libnacl.utils.load_key(sys.argv[1])

magicbytes = sys.stdin.buffer.read(2)

firstbytes = sys.stdin.buffer.read(struct.calcsize(fbformat))

version, metadatalength = struct.unpack(fbformat, firstbytes)

metabytes = sys.stdin.buffer.read(metadatalength)

metadata = dict(simpleubjson.decode(metabytes))

algorithm = metadata["algorithm"]

def unmapbytes(x):
    return bytes(x)
    #return [i.to_bytes(1, byteorder="big")[0] for i in x]

signkeybytes = unmapbytes(metadata["sign_key"])

sign_key = libnacl.public.SecretKey(signkeybytes)

securebytes = unmapbytes(metadata["secure"])

sbox = libnacl.public.Box(skey.sk, sign_key.pk)

securedecryptedbytes = sbox.decrypt(securebytes)

securedata = dict(simpleubjson.decode(securedecryptedbytes))

block_size = securedata["block_size"]

nonce_bytes = unmapbytes(securedata["nonce_bytes"])

sym_key = unmapbytes(securedata["key"])

counter_bytes = libnacl.crypto_box_NONCEBYTES - len(nonce_bytes)

def decrypt(data):
    counter = 0
    block = data.read(block_size)
    while len(block) > 0:
        cbytes = counter.to_bytes(counter_bytes, "big")
        nonce = nonce_bytes + cbytes
        dblock = libnacl.crypto_stream_xor(block, nonce, sym_key)
        yield dblock
        block = data.read(block_size)


for i in decrypt(sys.stdin.buffer):
    sys.stdout.buffer.write(i)
    
