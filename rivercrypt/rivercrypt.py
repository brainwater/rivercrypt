#!/usr/bin/python3
import argparse
import sys
import os
import os.path
import struct

import ubjson
import nacl
import nacl.utils
import nacl.secret
import nacl.public

# 16 bytes are used for signature
SECRET_BOX_SIGN_SIZE = 16


def getparser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-pk",
        "--public-key",
        type=str,
        help="Public key used for encryption or for checking the signature")
    parser.add_argument(
        "-sk",
        "--secret-key",
        type=str,
        help="Secret key used for decryption or for signing")
    parser.add_argument(
        "-va",
        "--verify-all",
        action="store_true",
        help=
        "Sign each chunk of the datastream if encrypting, or verify each chunk of the datastream if decrypting. This ensures data integrity. This is not yet supported"
    )
    parser.add_argument(
        "-d",
        "--decrypt",
        action="store_true",
        help="Decrypt stdin and put it on stdout")
    parser.add_argument(
        "-s",
        "--symmetric",
        action="store_true",
        help="Use symmetric encryption. This is not yet supported")
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help=
        "Force decryption when verification of signatures fail. Note: only applicable when decrypting a symmetric stream that has each chunk of the datastream signed. Useful for decrypting data that may have been slightly corrupted. This is not yet supported."
    )
    parser.add_argument(
        "-g",
        "--generate",
        action="store_true",
        help="Generate a secret and public key pair")
    parser.add_argument(
        "-bs",
        "--block-size",
        type=int,
        default=512,
        help="Block size of chunks in bytes")
    parser.add_argument(
        "-e",
        "--extract",
        action="store_true",
        help=
        "Extract the public key from a secret key, in case you lost the public key"
    )
    return parser


def parse():
    parser = getparser()
    return parser.parse_args()


# The first bytes (after the 2 magic bytes) are of 2 shorts in network byte order.
# it contains the version number followed by the number of bytes the metadata takes up
MAGIC_BYTES = b'BR'
FIRST_BYTES_FORMAT = "!HH"


def decrypt5(in_stream, out_stream, public_key, secret_key, verify_all,
             symmetric, force, block_size, metadata_length):
    metadata_bytes = in_stream.read(metadata_length)
    md = dict(ubjson.loadb(metadata_bytes))
    metadata = {}
    if public_key is not None:
        sign_key_encoded = public_key
    else:
        sign_key_encoded = md['sign_key']
        if md['sign_key'] != public_key:
            print(
                "WARNING: sign_key in metadata and public key provided don't match",
                file=sys.stderr)
    metadata['sign_key'] = nacl.public.PublicKey(sign_key_encoded)
    metadata['secret_key'] = nacl.public.PrivateKey(secret_key)

    decrypt_box = nacl.public.Box(metadata['secret_key'], metadata['sign_key'])
    secure_metadata_bytes = decrypt_box.decrypt(md['secure'])
    secure_metadata = dict(ubjson.loadb(secure_metadata_bytes))
    metadata["key"] = secure_metadata["key"]
    metadata["block_size"] = secure_metadata["block_size"]

    counter = 0
    decrypt_box = nacl.secret.SecretBox(metadata['key'])
    block_size = metadata['block_size'] + SECRET_BOX_SIGN_SIZE
    block = in_stream.read(block_size)
    while len(block) > 0:
        # Use network endianness
        counternonce = counter.to_bytes(nacl.secret.SecretBox.NONCE_SIZE,
                                        "big")
        out_block = decrypt_box.decrypt(block, nonce=counternonce)
        out_stream.write(out_block)
        block = in_stream.read(block_size)
        counter += 1
    return


def encrypt5(in_stream, out_stream, public_key, secret_key, verify_all,
             symmetric, force, block_size):
    version = 5
    sym_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    if None == secret_key:
        sign_key = nacl.public.PrivateKey.generate()
    else:
        sign_key = nacl.public.PrivateKey(secret_key)

    print(sym_key)
    secure_metadata = {
        "key": sym_key,
        "block_size": block_size,
    }
    secure_metadata_bytes = ubjson.dumpb(secure_metadata)
    public_key = nacl.public.PublicKey(public_key)
    smdbox = nacl.public.Box(sign_key, public_key)
    encrypted_metadata = bytes(smdbox.encrypt(secure_metadata_bytes))
    metadata = {
        "sign_key": sign_key.public_key.encode(),
        "secure": encrypted_metadata,
    }
    encoded_metadata = ubjson.dumpb(metadata)
    metadata_length = len(encoded_metadata)
    first_bytes = struct.pack(FIRST_BYTES_FORMAT, version, metadata_length)

    out_stream.write(MAGIC_BYTES)
    out_stream.write(first_bytes)
    out_stream.write(encoded_metadata)
    # Using predictable nonces (but never twice for the same key)
    # there is a 3% size overhead due to the 16 byte signatures,
    # instead of a 7.8% size overhead due to a 40 byte signature+nonce
    counter = 0
    encrypter_box = nacl.secret.SecretBox(sym_key)
    block = in_stream.read(block_size)
    while len(block) > 0:
        # Use network endianness
        counternonce = counter.to_bytes(nacl.secret.SecretBox.NONCE_SIZE,
                                        "big")
        out_block = encrypter_box.encrypt(
            block, nonce=counternonce)._ciphertext
        # We are counting on this for the decryption
        assert len(out_block) == SECRET_BOX_SIGN_SIZE + len(block)
        out_stream.write(out_block)
        block = in_stream.read(block_size)
        counter += 1
    return


def encrypt(in_stream, out_stream, public_key, secret_key, verify_all,
            symmetric, force, block_size):
    # if version == 3:
    #    #return encrypt3(in_stream, out_stream, public_key, secret_key, verify_all, symmetric, force, block_size)
    #    pass
    # elif version == 4:
    return encrypt5(in_stream, out_stream, public_key, secret_key, verify_all,
                    symmetric, force, block_size)


def decrypt(in_stream, out_stream, public_key, secret_key, verify_all,
            symmetric, force, block_size):
    mBytes = in_stream.read(len(MAGIC_BYTES))
    if mBytes != MAGIC_BYTES:
        raise Exception("Unknown magic number: " + str(mBytes))
    first_bytes = in_stream.read(struct.calcsize(FIRST_BYTES_FORMAT))
    version, metadata_length = struct.unpack(FIRST_BYTES_FORMAT, first_bytes)
    if 3 == version:
        decrypt3(in_stream, out_stream, public_key, secret_key, verify_all,
                 symmetric, force, block_size, metadata_length)
    elif version == 4:
        decrypt4(in_stream, out_stream, public_key, secret_key, verify_all,
                 symmetric, force, block_size, metadata_length)
    elif version == 5:
        decrypt5(in_stream, out_stream, public_key, secret_key, verify_all,
                 symmetric, force, block_size, metadata_length)
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
        seckey = nacl.public.PrivateKey.generate()
        pubkey = seckey.public_key
        with open(secret_key, 'wb') as skf:
            skf.write(seckey.encode())
        with open(public_key, 'wb') as pkf:
            pkf.write(pubkey.encode())
    return


def genkey():
    seckey = nacl.public.PrivateKey.generate()
    pubkey = seckey.public_key
    return pubkey.encode(), seckey.encode()


def decstream(in_stream, out_stream, public_key, secret_key):
    args = getparser().parse_args([])
    args.decrypt = True
    decrypt(
        in_stream=in_stream,
        out_stream=out_stream,
        public_key=public_key,
        secret_key=secret_key,
        verify_all=args.verify_all,
        symmetric=args.symmetric,
        force=args.force,
        block_size=args.block_size)
    return


def encstream(in_stream, out_stream, public_key, secret_key):
    args = getparser().parse_args([])
    args.decrypt = False
    encrypt(
        in_stream=in_stream,
        out_stream=out_stream,
        public_key=public_key,
        secret_key=secret_key,
        verify_all=args.verify_all,
        symmetric=args.symmetric,
        force=args.force,
        block_size=args.block_size)
    return


def loadfile(filename):
    with open(filename, 'rb') as f:
        contents = f.read()
    return contents


def extract(public_key, secret_key):
    if None == public_key or None == secret_key:
        sys.exit(
            "Please specify a secret key and a path to save the public key")
    elif os.path.exists(public_key):
        sys.exit("Public key already exists, exiting")
    elif not os.path.exists(secret_key):
        sys.exit("Secret key does not exist, exiting")
    else:
        seckey = nacl.public.PrivateKey(secret_key)
        pubkey = seckey.public_key
        with open(public_key, 'wb') as pkf:
            pkf.write(pubkey.encode())
    return


def main():
    args = parse()
    if args.generate:
        generate(
            public_key=args.public_key,
            secret_key=args.secret_key,
            symmetric=args.symmetric)
    elif args.extract:
        extract(public_key=args.public_key, secret_key=args.secret_key)
    else:
        if None != args.public_key:
            public_key = loadfile(args.public_key)
        else:
            public_key = None
        if None != args.secret_key:
            secret_key = loadfile(args.secret_key)
        else:
            secret_key = None
        if args.decrypt:
            decrypt(
                in_stream=sys.stdin.buffer,
                out_stream=sys.stdout.buffer,
                public_key=public_key,
                secret_key=secret_key,
                verify_all=args.verify_all,
                symmetric=args.symmetric,
                force=args.force,
                block_size=args.block_size)
        else:
            encrypt(
                in_stream=sys.stdin.buffer,
                out_stream=sys.stdout.buffer,
                public_key=public_key,
                secret_key=secret_key,
                verify_all=args.verify_all,
                symmetric=args.symmetric,
                force=args.force,
                block_size=args.block_size)


if __name__ == "__main__":
    main()
