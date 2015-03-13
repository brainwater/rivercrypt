import sys
import libnacl.public


# Generates a keypair. Saves the public key to the first argument, and saves the secret key to the second argument.

pub_file = sys.argv[1]
priv_file = sys.argv[2]

skey = libnacl.public.SecretKey()
pkey = libnacl.public.PublicKey(skey.pk)

pkey.save(pub_file)
skey.save(priv_file)
