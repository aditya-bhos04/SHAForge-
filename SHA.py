#!/usr/bin/python
import hashlib
import base64
import argparse
import sys

class SHA():
    def __init__(self,cipher):
        self.cipher = cipher

    # Functions to Encode the strings using SHA Algorithm
    def sha1(self):
        cipher = self.cipher
        output = hashlib.sha1(cipher.encode()).hexdigest()
        print(output)

    def sha224(self):
        cipher = self.cipher
        output = hashlib.sha224(cipher.encode()).hexdigest()
        print(output)

    def sha256(self):
        cipher = self.cipher
        output = hashlib.sha256(cipher.encode()).hexdigest()
        print(output)

    def sha384(self):
        cipher = self.cipher
        output = hashlib.sha384(cipher.encode()).hexdigest()
        print(output)

    def sha512(self):
        cipher = self.cipher
        output = hashlib.sha512(cipher.encode()).hexdigest()
        print(output)

    def md5(self):
        cipher = self.cipher
        output = hashlib.md5(cipher.encode()).hexdigest()
        print(output)



if __name__ == '__main__':

    pars = argparse.ArgumentParser(description='Python tool to encode your String',
                                   epilog='python %(prog)s <sha algorithm> <cipher>',
                                   usage='python %(prog)s --sha256 Hello')
    
    pars.add_argument('--sha1',
                      dest='sha1',
                      help='Used to Encode the String using SHA1 Algorithm\n',
                      nargs=1)
    
    pars.add_argument('--sha256',
                      dest='sha256',
                      help='Used to Encode the String using SHA256 Algorithm',
                      nargs=1)
    
    pars.add_argument('--sha384',
                      dest='sha384',
                      help='Used to Encode the String using SHA384 Algorithm',
                      nargs=1)
    
    pars.add_argument('--sha512',
                      dest='sha512',
                      help='Used to Encode the String using SHA512 Algorithm',
                      nargs=1)
    
    pars.add_argument('--sha224',
                      dest='sha224',
                      help='Used to Encode the String using SHA224 Algorithm',
                      nargs=1)
    
    pars.add_argument('--md5',
                      dest='md5',
                      help='Used to Encode the String using MD5 Algorithm',
                      nargs=1)

    pars.add_argument('--scrypt',
                      dest='scrypt',
                      help='Used to Encode the String using SCRYPT Algorithm',
                      nargs=1)
    
    arg = pars.parse_args()
    sha1 = arg.sha1
    sha224 = arg.sha224
    sha256 = arg.sha256
    sha384 = arg.sha384
    sha512 = arg.sha512
    md5 = arg.md5
    scrypt = arg.scrypt
        
    # Print the help message
    if len(sys.argv) <=2:
        pars.print_help()     

    # If any of these are their in the arguments, functions will be called accordingly
    if '--sha1' or '--sha224' or '--sha256' or '--sha384' or '--sha512' or '--md5' in sys.argv:
        try:
            encode = SHA(sys.argv[2])
        except Exception as e:
            print('')

    if sha1:
        encode.sha1()

    if sha224:
        encode.sha224()

    if sha256:
        encode.sha256()

    if sha384:
        encode.sha384()

    if sha512:
        encode.sha512()

    if scrypt:
        encode.scrypt()

    if md5:
        encode.md5()
