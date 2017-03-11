#!/usr/bin/python3
import sys
import struct
import os.path
import argparse
import simpleubjson
import libnacl
import libnacl.utils
import libnacl.public
import ubjson
import hmac


def getparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-pk", "--public-key", type=str, help="Public key used for encryption or for checking the signature")
    parser.add_argument("-sk", "--secret-key", type=str, help="Secret key used for decryption or for signing")
    parser.add_argument("-va", "--verify-all", action="store_true", help="Sign each chunk of the datastream if encrypting, or verify each chunk of the datastream if decrypting. This ensures data integrity. This is not yet supported")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt stdin and put it on stdout")
    parser.add_argument("-s", "--symmetric", action="store_true", help="Use symmetric encryption. This is not yet supported")
    parser.add_argument("-f", "--force", action="store_true", help="Force decryption when verification of signatures fail. Note: only applicable when decrypting a symmetric stream that has each chunk of the datastream signed. Useful for decrypting data that may have been slightly corrupted. This is not yet supported.")
    parser.add_argument("-g", "--generate", action="store_true", help="Generate a secret and public key pair")
    parser.add_argument("-bs", "--block-size", type=int, default=512, help="Block size of chunks in bytes")
    return parser
def parse():
    parser = getparser()
    return parser.parse_args()

MAGIC_BYTES = b'BR'
FIRST_BYTES_FORMAT = "!HH"
NONCE_COUNTER_BYTES = 30

# mapbytes and unmapbtyes are used to get around a bug in simpleubjson where it decodes a byte array as a string, so with invalid unicode values in python3 it will fail hard. Instead I map it to a list of ints.
def mapbytes(xs):
    return [int(i) for i in xs]

def unmapbytes(xs):
    return bytes(xs)

def encdecroutine3(in_stream, out_stream, key, block_size, nonce_bytes, num_counter_bytes):
    counter = 0
    block = in_stream.read(block_size)
    while len(block) > 0:
        # Will except out if number is too big to fit in num_counter_bytes
        counter_bytes = counter.to_bytes(num_counter_bytes, "big")
        nonce = nonce_bytes + counter_bytes
        encrypted_block = libnacl.crypto_stream_xor(block, nonce, key)
        out_stream.write(encrypted_block)
        block = in_stream.read(block_size)

# I am foregoing support for format versions 1 and 2 since I have not yet released this to simplify the code
def decrypt3(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size, metadata_length):
    metadata_bytes = in_stream.read(metadata_length)
    md = dict(simpleubjson.decode(metadata_bytes))
    metadata = {
        "algorithm": md["algorithm"],
        "sign_key": unmapbytes(md["sign_key"]),
    }
    encrypted_metadata_bytes = unmapbytes(md["secure"])
    sign_key = libnacl.public.PublicKey(metadata["sign_key"])
    if None != public_key and sign_key.pk != public_key.pk:
        raise Exception("Metadata failed to pass signature verification")
    smdbox = libnacl.public.Box(secret_key.sk, sign_key.pk)
    secure_metadata_bytes = smdbox.decrypt(encrypted_metadata_bytes)
    smd = dict(simpleubjson.decode(secure_metadata_bytes))
    metadata["key"] = unmapbytes(smd["key"])
    metadata["nonce_bytes"] = unmapbytes(smd["nonce_bytes"])
    metadata["block_size"] = smd["block_size"]
    num_counter_bytes = libnacl.crypto_box_NONCEBYTES - len(metadata["nonce_bytes"])

    encdecroutine3(in_stream, out_stream, metadata["key"], metadata["block_size"], metadata["nonce_bytes"], num_counter_bytes)
    return

def encrypt3(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size):
    version = 3
    # The first bytes (after the 2 magic bytes) are of 2 shorts in network byte order.
    # it contains the version number followed by the number of bytes the metadata takes up
    # TODO: reduce the counter bytes and instead redo the encryption or have another random nonce when the counter bytes run out, so we can support arbitrary size streams.
    # Currently, it will error out with a stream larger than (2^(8*counter_bytes) * block_size) bytes
    # For the defaults of 5 and 512, that is 512 TiB, which is probably enough for any usage of it in the next couple of years, but as we all know, eventually we will want more.
    # I don't want to increase counter_bytes any more, since if counter_bytes is increased, then the likelyhood of this nonce being reused is increased. Do I need to worry about that if the secret key is regenerated each time? I may just be able to increase counter_bytes significantly.
    num_counter_bytes = 5
    # TODO: support symmetric encryption
    sym_key = libnacl.utils.salsa_key()
    nonce_bytes = libnacl.randombytes(libnacl.crypto_box_NONCEBYTES - num_counter_bytes)
    if None == secret_key:
        sign_key = libnacl.public.SecretKey()
    else:
        sign_key = secret_key

    secure_metadata = {
        "key": mapbytes(sym_key),
        "nonce_bytes": mapbytes(nonce_bytes),
        "block_size": block_size,
    }
    bin_secure_metadata = simpleubjson.encode(secure_metadata)
    smdbox = libnacl.public.Box(sign_key.sk, public_key.pk)
    encrypted_metadata = smdbox.encrypt(bin_secure_metadata)
    metadata = {
        "algorithm": "asymmetric-vblock-curve25519-salsa20",
        "sign_key": mapbytes(sign_key.pk),
        "secure": mapbytes(encrypted_metadata),
    }
    encoded_metadata = simpleubjson.encode(metadata)
    metadata_length = len(encoded_metadata)
    first_bytes = struct.pack(FIRST_BYTES_FORMAT, version, metadata_length)

    out_stream.write(MAGIC_BYTES)
    out_stream.write(first_bytes)
    out_stream.write(encoded_metadata)

    encdecroutine3(in_stream, out_stream, sym_key, block_size, nonce_bytes, num_counter_bytes)
    
    return

def schedule_nonce(initialkey, idx, numbytes):
    msg = idx.to_bytes(NONCE_COUNTER_BYTES, "big")
    h = hmac.new(initialkey, msg=msg, digestmod='sha512')
    return h.digest()

def encdecroutine4(in_stream, out_stream, key, block_size, initial_nonce, num_counter_bytes):
    counter = 0
    block = in_stream.read(block_size)
    while len(block) > 0:
        # Will except out if number is too big to fit in int with number of bytes NONCE_COUNTER_BYTES
        #counter_bytes = counter.to_bytes(num_counter_bytes, "big")
        nonce = schedule_nonce(initial_nonce, counter, libnacl.crypto_box_NONCEBYTES)
        counter += 1
        encrypted_block = libnacl.crypto_stream_xor(block, nonce, key)
        out_stream.write(encrypted_block)
        block = in_stream.read(block_size)
    return
def decrypt4(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size, metadata_length):
    metadata_bytes = in_stream.read(metadata_length)
    md = dict(ubjson.loadb(metadata_bytes))
    metadata = {
        "sign_key": md["sign_key"],
    }
    encrypted_metadata_bytes = md["secure"]
    sign_key = libnacl.public.PublicKey(metadata["sign_key"])
    if None != public_key and sign_key.pk != public_key.pk:
        raise Exception("Metadata failed to pass signature verification")
    smdbox = libnacl.public.Box(secret_key.sk, sign_key.pk)
    secure_metadata_bytes = smdbox.decrypt(encrypted_metadata_bytes)
    smd = dict(ubjson.loadb(secure_metadata_bytes))
    metadata["key"] = smd["key"]
    metadata["nonce_bytes"] = smd["nonce_bytes"]
    metadata["block_size"] = smd["block_size"]
    num_counter_bytes = libnacl.crypto_box_NONCEBYTES

    encdecroutine4(in_stream, out_stream, metadata["key"], metadata["block_size"], metadata["nonce_bytes"], num_counter_bytes)
    return

def encrypt4(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size):
    version = 4
    sym_key = libnacl.utils.salsa_key()
    sign_key = secret_key
    if None == secret_key:
        sign_key = libnacl.public.SecretKey()
    noncesize = max(libnacl.crypto_box_NONCEBYTES, 64)
    nonce_bytes = libnacl.randombytes(noncesize)
    secure_metadata = {
        "key": sym_key,
        "nonce_bytes": nonce_bytes,
        "block_size": block_size,
    }
    secure_metadata_bytes = ubjson.dumpb(secure_metadata)
    smdbox = libnacl.public.Box(sign_key.sk, public_key.pk)
    encrypted_metadata = smdbox.encrypt(secure_metadata_bytes)
    metadata = {
        "sign_key": sign_key.pk,
        "secure": encrypted_metadata,
    }
    encoded_metadata = ubjson.dumpb(metadata)
    metadata_length = len(encoded_metadata)
    first_bytes = struct.pack(FIRST_BYTES_FORMAT, version, metadata_length)

    out_stream.write(MAGIC_BYTES)
    out_stream.write(first_bytes)
    out_stream.write(encoded_metadata)
    encdecroutine4(in_stream, out_stream, sym_key, block_size, nonce_bytes, libnacl.crypto_box_NONCEBYTES)
    

def encrypt(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size):
    #if version == 3:
    #    #return encrypt3(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size)
    #    pass
    #elif version == 4:
    return encrypt4(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size)

def decrypt(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size):
    mBytes = in_stream.read(len(MAGIC_BYTES))
    if mBytes != MAGIC_BYTES:
        raise Exception("Unknown magic number: " + str(mBytes))
    first_bytes = in_stream.read(struct.calcsize(FIRST_BYTES_FORMAT))
    version, metadata_length = struct.unpack(FIRST_BYTES_FORMAT, first_bytes)
    if 3 == version:
        decrypt3(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size, metadata_length)
    elif version == 4:
        decrypt4(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size, metadata_length)
    else:
        raise Exception("Unsupported format version: " + str(version))
    return

def generate(public_key, secret_key, symmetric):
    if None == public_key or None == secret_key:
        sys.exit("Please specify a public key and a secret key")
    elif os.path.exists(public_key):
        sys.exit("Public key already exists, exiting")
    elif os.path.exists(secret_key):
        sys.exit("Secret key already exists, exiting")
    else:
        seckey = libnacl.public.SecretKey()
        pubkey = libnacl.public.PublicKey(seckey.pk)
        seckey.save(secret_key)
        pubkey.save(public_key)
    return

def decstream(in_stream, out_stream, public_key, secret_key):
    args = getparser().parse_args([])
    args.decrypt = True
    decrypt(in_stream=in_stream, out_stream=out_stream, public_key=public_key, secret_key=secret_key, verify_all=args.verify_all, symmetric=args.symmetric, force=args.force, block_size=args.block_size)
    return
    
def encstream(in_stream, out_stream, public_key, secret_key):
    args = getparser().parse_args([])
    args.decrypt = False
    encrypt(in_stream=in_stream, out_stream=out_stream, public_key=public_key, secret_key=secret_key, verify_all=args.verify_all, symmetric=args.symmetric, force=args.force, block_size=args.block_size)
    return

def loadkey(filename):
    return libnacl.utils.load_key(filename)

def main():
    args = parse()
    if args.generate:
        generate(public_key=args.public_key, secret_key=args.secret_key, symmetric=args.symmetric)
    else:
        if None != args.public_key:
            public_key = loadkey(args.public_key)
        else:
            public_key = None
        if None != args.secret_key:
            secret_key = loadkey(args.secret_key)
        else:
            secret_key = None
        if args.decrypt:
            decrypt(in_stream=sys.stdin.buffer, out_stream=sys.stdout.buffer, public_key=public_key, secret_key=secret_key, verify_all=args.verify_all, symmetric=args.symmetric, force=args.force, block_size=args.block_size)
        else:
            encrypt(in_stream=sys.stdin.buffer, out_stream=sys.stdout.buffer, public_key=public_key, secret_key=secret_key, verify_all=args.verify_all, symmetric=args.symmetric, force=args.force, block_size=args.block_size)

if __name__ == "__main__":
    main()
