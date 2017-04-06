# rivercrypt
Simple unix style utility for asymmetrically encrypting and decrypting files in a shell pipeline

## Usage
```
usage: rivercrypt.py [-h] [-pk PUBLIC_KEY] [-sk SECRET_KEY] [-va] [-d] [-s]
                     [-f] [-g] [-bs BLOCK_SIZE]

optional arguments:
  -h, --help            show this help message and exit
  -pk PUBLIC_KEY, --public-key PUBLIC_KEY
                        Public key used for encryption or for checking the
                        signature
  -sk SECRET_KEY, --secret-key SECRET_KEY
                        Secret key used for decryption or for signing
  -va, --verify-all     Sign each chunk of the datastream if encrypting, or
                        verify each chunk of the datastream if decrypting.
                        This ensures data integrity. This is not yet supported
  -d, --decrypt         Decrypt stdin and put it on stdout
  -s, --symmetric       Use symmetric encryption. This is not yet supported
  -f, --force           Force decryption when verification of signatures fail.
                        Note: only applicable when decrypting a symmetric
                        stream that has each chunk of the datastream signed.
                        Useful for decrypting data that may have been slightly
                        corrupted. This is not yet supported.
  -g, --generate        Generate a secret and public key pair
  -bs BLOCK_SIZE, --block-size BLOCK_SIZE
                        Block size of chunks in bytes
```
## Examples
Takes standard input and encrypts/decrypts it to standard output

```$ ./rivercrypt.py -g -pk ~/temp/public_key -sk ~/temp/secret_key```

```$ cat ~/temp/testfile.txt | ./rivercrypt.py -pk ~/temp/public_key > ~/temp/encryptedtestfile.txt.rca```

```$ cat ~/temp/encryptedtestfile.rca | ./rivercrypt.py -sk ~/temp/secret_key > ~/temp/decryptedtestfile.txt```

## Requirements
python3, python3-pip

On debian and debian derivatives run 
```$ sudo apt-get install python3 python3-pip```
then from the directory where you have downloaded rivercrypt
```$ sudo pip3 install -r requirements.txt```

## Not yet implemented
Symmetric encryption

Full data signing and verification

This means that the flags -s, -va, and -f have no meaning right now.

## Motivation
I wanted a simple and secure asymmetric encryption utility to encrypt my backups.
If my backup machine was comprimised, I didn't want my backups to be comprimised as well.
Initially I considered using gpg, however was concerned when I read that it only supported 1024 bit asymmetric keys due to compatibility requirements.
In addition, gpg wasn't exactly simple to use.
I thought about what the perfect utility would act like, and came up with the following.
It would take a public key and then encrypt stdin using that public key to stdout.
When decrypting, it would take the secret key and decrypt stdin to stdout.
This would allow me to create a secret key on a secure machine and save it with the rest of my sensitive data.
On the backup machine, I would only have to save the public key and would not have to worry about the encrypted data being comprimised.

## Disclaimer
This source code has not been audited and is not in a production ready state.
In addition, this relies on the libnacl python package that has also not been audited to the best of my knowledge.
I am not a cryptography professional, however I did try to follow the best practices.
I may have made a mistake that would cause this to not be reliable or secure.
I am providing this softare as-is and make no warranty as to the security or integrity of this software.

With that said, I believe that this is secure, though I wouldn't yet use this to encrypt my passwords file and then publish it on pastebin. That was wrong to believe when said. With format version 3, the nonce used was the same for each and every block, causing the encryption to be easily broken.
