"""Python One-Time-Pad by James Lamphere
This is a simple implementation of a Python one time pad system.
You may either use the class on its own, or run it itself.
It accepts file names for all arguments.

Usage:
  one_time_pad.py enc <input> [<cipher>]
  one_time_pad.py dec <input> <cipher>

Options:
  -h --help     Show this screen.

"""
from docopt import docopt
import string
import random
import sys
import os


class OTP(object):
    def __init__(self, pad_len=0, cipher=''):
        if pad_len:
            self.cipher = ''.join(random.sample(string.ascii_letters, pad_len))
        elif cipher:
            self.cipher = cipher
        else:
            raise Exception("You didnt provide a cipher, or how long the message will be...")

    def encrypt(self, plain_message):
        return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(plain_message, self.cipher)])

    def decrypt(self, enc_message):
        return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(enc_message, self.cipher)])

if __name__ == "__main__":
    cipher = ''
    arguments = docopt(__doc__, version='One Time Pad')
    if os.path.exists(arguments['<input>']):
        message = open(arguments['<input>'], 'rb').read()
    else:
        raise Exception("No input file given.")
    if arguments['<cipher>']:
        if os.path.exists(arguments['<cipher>']):
            cipher = open(arguments['<cipher>'], 'rb').read()
        else:
            raise Exception("No cipher file given.")
        # Make sure the cipher we're going to use it the same length as the message
        cipher += ''.join(random.sample(string.ascii_letters, len(message) - len(cipher)))[0:len(message)]
    pad = OTP(cipher=cipher) if cipher else OTP(len(message))
    print "[?] Cipher: %s" % pad.cipher
    if arguments['enc']:
        out_ = sys.argv[2] + ".enc"
        cipher_ = sys.argv[2] + ".cipher"
        with open(out_, "wb") as o:
            o.write(pad.encrypt(message))
        with open(cipher_, "wb") as o:
            o.write(pad.cipher)
        print "[+] Encrypted File Written To '%s', Cipher to '%s'" % (out_, cipher_)
    else:
        out_ = sys.argv[2] + ".dec"
        with open(out_, "wb") as o:
            o.write(pad.decrypt(message))
        print "[+] Decrypted File Written To '%s'" % out_