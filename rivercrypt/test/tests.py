import rivercrypt
import unittest
import os
import os.path
import io
import random

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


class CurrentVersionTestCase(unittest.TestCase):
    def setUp(self):
        self.testfiles = {}
        """testfiledir = os.path.join(TEST_DIR, 'data', 'testfiles')
        for fname in os.listdir(testfiledir):
            testfile = os.path.join(testfiledir, fname)
            with open(testfile, 'rb') as tf:
                self.testfiles[fname] = tf.read()"""
        random.seed(42)
        for i in range(10):
            flen = random.randrange(1000000)
            self.testfiles[i] = os.urandom(flen)
        self.pkeys, self.skeys = zip(*[rivercrypt.genkey() for i in range(5)])
        
        #keyfiledir = os.path.join(TEST_DIR, 'keys')
        """for f in sorted(os.listdir(keyfiledir)):
            if f.startswith('secretkey'):
                self.skeys.append(rivercrypt.loadkey(
                    os.path.join(keyfiledir, f)))
            elif f.startswith('publickey'):
                self.pkeys.append(rivercrypt.loadkey(
                    os.path.join(keyfiledir, f)))"""
        
        self.assertEqual(len(self.skeys), len(self.pkeys))
        self.pairs = []
        for i in range(len(self.skeys)):
            for j in range(len(self.pkeys)):
                if i != j:
                    self.pairs.append((i, j))
        self.encfiles = {}
        for s, p in self.pairs:
            print('Encrypting with keys:', (s, p))
            self.encfiles[(s, p)] = {}
            for f in self.testfiles:
                print('Encrypting file:', f)
                with io.BytesIO(self.testfiles[f]) as stream:
                    with io.BytesIO() as outstream:
                        rivercrypt.encstream(
                            stream, outstream, self.pkeys[p], self.skeys[s])
                        data = outstream.getvalue()
                        self.encfiles[(s, p)][f] = data

    def test_decryption(self):
        for s, p in self.pairs:
            print('Testing with keys:', (s, p))
            for f in self.testfiles:
                print('Testing file:', f)
                with io.BytesIO(self.encfiles[(s, p)][f]) as instream:
                    with io.BytesIO() as outstream:
                        rivercrypt.decstream(
                            instream, outstream, self.pkeys[s], self.skeys[p])
                        self.assertEqual(
                            self.testfiles[f], outstream.getvalue())
