#!/usr/bin/python

import sys
import struct
import array
import libnacl
import libnacl.utils
import libnacl.public
import simpleubjson

versionformat = "!H"
metadatalengthformat = "!H"

# Used for decrypting files encrypted with enc-util

def unmapbytes(x):
    return bytes(x)

def getRawMetadata(stdin):
    # Must be called after reading the magic bytes and version but before anything else
    mdLenBytes = stdin.read(struct.calcsize(metadatalengthformat))
    (mdLen,) = struct.unpack(metadatalengthformat, mdLenBytes)
    mdBytes = stdin.read(mdLen)
    return mdBytes

def v1MetadataDecode(skey, mdBytes):
    md = dict(simpleubjson.decode(mdBytes))
    metadata = {
        "algorithm": md["algorithm"],
        "sign_key": unmapbytes(md["sign_key"]),
    }
    smdBytes = unmapbytes(md["secure"])
    signKey = libnacl.public.SecretKey(metadata["sign_key"])
    smdBox = libnacl.public.Box(skey.sk, signKey.pk)
    smdDBytes = smdBox.decrypt(smdBytes)
    smd = dict(simpleubjson.decode(smdDBytes))
    secureMetadata = {
        "key": unmapbytes(smd["key"]),
        "nonce_bytes": unmapbytes(smd["nonce_bytes"]),
        "block_size": smd["block_size"]
    }
    return metadata, secureMetadata

def v1Decrypt(key, stdin, stdout, numCounterBytes, blockSize, nonceBytes):
    counter = 0
    block = stdin.read(blockSize)
    while len(block) > 0:
        cbytes = counter.to_bytes(numCounterBytes, "big")
        nonce = nonceBytes + cbytes
        dblock = libnacl.crypto_stream_xor(block, nonce, key)
        stdout.write(dblock)
        block = stdin.read(blockSize)

def v1Decode(skey, stdin, stdout):
    mdBytes = getRawMetadata(stdin)
    md, smd = v1MetadataDecode(skey, mdBytes)
    nonce_bytes = smd["nonce_bytes"]
    block_size = smd["block_size"]
    sym_key = smd["key"]
    counter_bytes = libnacl.crypto_box_NONCEBYTES - len(nonce_bytes)
    v1Decrypt(sym_key, stdin, stdout, counter_bytes, block_size, nonce_bytes)

def v2MetadataDecode(skey, mdBytes):
    md = dict(simpleubjson.decode(mdBytes))
    metadata = {
        "algorithm": md["algorithm"],
        "sign_key": unmapbytes(md["sign_key"]),
    }
    smdBytes = unmapbytes(md["secure"])
    # Version 2 stores the public key of the key used to sign the box
    signKey = libnacl.public.PublicKey(metadata["sign_key"])
    smdBox = libnacl.public.Box(skey.sk, signKey.pk)
    smdDBytes = smdBox.decrypt(smdBytes)
    smd = dict(simpleubjson.decode(smdDBytes))
    secureMetadata = {
        "key": unmapbytes(smd["key"]),
        "nonce_bytes": unmapbytes(smd["nonce_bytes"]),
        "block_size": smd["block_size"]
    }
    return metadata, secureMetadata
    

def v2Decode(skey, stdin, stdout):
    mdBytes = getRawMetadata(stdin)
    md, smd = v2MetadataDecode(skey, mdBytes)
    nonce_bytes = smd["nonce_bytes"]
    block_size = smd["block_size"]
    sym_key = smd["key"]
    counter_bytes = libnacl.crypto_box_NONCEBYTES - len(nonce_bytes)
    v1Decrypt(sym_key, stdin, stdout, counter_bytes, block_size, nonce_bytes)

def main(skey, stdin, stdout):
    magicbytes = sys.stdin.buffer.read(2)
    if b'BR' != magicbytes:
        raise Exeption("Unknown magic number")
    versionbytes = sys.stdin.buffer.read(struct.calcsize(versionformat))
    (version,) = struct.unpack(versionformat, versionbytes)
    if 1 == version:
        v1Decode(skey, stdin, stdout)
    elif 2 == version:
        v2Decode(skey, stdin, stdout)
    else:
        raise Exeption("Unsupported version: " + str(version))

if __name__ == "__main__":
    skey = libnacl.utils.load_key(sys.argv[1])
    main(skey, sys.stdin.buffer, sys.stdout.buffer)


