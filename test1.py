import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
    Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES


class Libutils:

    @staticmethod
    def pad(msg):
        # pkcs7 padding
        num = 16 - (len(msg) % 16)
        return msg + bytes([num] * num)

    @staticmethod
    def unpad(msg):
        # remove pkcs7 padding
        return msg[:-msg[-1]]

    @staticmethod
    def b64(msg):
        # base64 encoding helper function
        return base64.encodebytes(msg).decode('utf-8').strip()

    @staticmethod
    def hkdf(inp, length):
        # use HKDF on an input to derive a key
        hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'',
                    info=b'', backend=default_backend())
        return hkdf.derive(inp)


class SymmRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = Libutils.hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv


class user(object):

    # Initialize Ratchet state
    __DHratchet = None

    def __init__(self, name):
        # generate Bob's keys
        self.__name = name
        # Identity
        self.__IPK = X25519PrivateKey.generate()
        # Pre signed key
        self.__SPK = X25519PrivateKey.generate()
        # One time pre key
        self.__OPK = X25519PrivateKey.generate()
        # Ephemeral key
        self.__EFK = X25519PrivateKey.generate()


alice = user("alice")
bob = user("bob")
