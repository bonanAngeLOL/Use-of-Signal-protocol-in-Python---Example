import base64
import json
import sys
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
    Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
import os
import _pickle as cPickle

import socket

HOST = '127.0.0.1'  # La dirección IP del host del socket
PORT = 8085


@dataclass
class UserKeys:
    IPK: object = None
    SPK: object = None
    EFK: object = None
    OPK: object = None


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

    @staticmethod
    def key_to_bytes(keyObj: object):
        return (base64.b64encode(keyObj._raw_public_bytes())).decode("utf8")


class Protocol:
    _sk: object = None

    def get_ipk(self):
        pass

    def get_spk(self):
        pass

    def get_opk(self):
        pass

    def get_efk(self):
        pass

    def receive_x3dh(self, sender):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.IKa.exchange(sender.SPK)
        dh2 = self.EKa.exchange(sender.IK)
        dh3 = self.EKa.exchange(sender.SPK)
        dh4 = self.EKa.exchange(sender.OPK)
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self._sk = Libutils.hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Alice]\tShared key:', Libutils.b64(self._sk))


class SymmRatchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, inp=b''):
        # turn the ratchet, changing the state and yielding a new key and IV
        output = Libutils.hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv


class User:

    # Initialize Ratchet state
    __DHratchet: X25519PrivateKey = None
    __sk: object
    __root_ratchet: object
    __send_ratchet: object
    __recv_ratchet: object

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

    # Private key remains private. While public key
    # are generated from then and published via getter
    def get_ipk(self):
        return self.__IPK.public_key()

    def get_spk(self):
        return self.__SPK.public_key()

    def get_opk(self):
        return self.__OPK.public_key()

    def get_efk(self):
        return self.__EFK.public_key()

    def next_send(self):
        return self.__send_ratchet.next()

    def next_recv(self):
        return self.__recv_ratchet.next()

    def get_name(self):
        return self.__name

    def keys_prepared_send(self):
        UserKeys = self.keys_to_server()
        return json.dumps({
            "command": "auth",
            "user": self.__name,
            "SPK": Libutils.key_to_bytes(UserKeys.SPK),
            "IPK": Libutils.key_to_bytes(UserKeys.IPK),
            "OPK": Libutils.key_to_bytes(UserKeys.OPK),
            "EFK": Libutils.key_to_bytes(UserKeys.EFK)
        }).encode("utf8")

    def keys_to_server(self):
        return UserKeys(
            SPK=self.get_spk(),
            IPK=self.get_ipk(),
            OPK=self.get_opk(),
            EFK=self.get_efk()
        )

    def get_DHpublic(self):
        if self.__DHratchet is None:
            self.__DHratchet = X25519PrivateKey.generate()
        return self.__DHratchet.public_key()

    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.__root_ratchet = SymmRatchet(self.__sk)
        # initialise the sending and recving chains
        self.__send_ratchet = SymmRatchet(self.__root_ratchet.next()[0])
        self.__recv_ratchet = SymmRatchet(self.__root_ratchet.next()[0])

    def start_x3dh(self, sender):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.__IPK.exchange(sender.SPK)
        dh2 = self.__EFK.exchange(sender.IPK)
        dh3 = self.__EFK.exchange(sender.SPK)
        OPK = sender.OPK
        dh4 = self.__EFK.exchange(OPK)
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.__sk = Libutils.hkdf(dh1 + dh2 + dh3 + dh4, 32)
        # print('[Alice]\tShared key:', Libutils.b64(self.__sk))

    def responding_x3dh(self, recipient):
        # perform the 4 Diffie Hellman exchanges (X3DH)
        dh1 = self.__SPK.exchange(recipient.IPK)
        dh2 = self.__IPK.exchange(recipient.EFK)
        dh3 = self.__SPK.exchange(recipient.EFK)
        dh4 = self.__OPK.exchange(recipient.EFK)
        # the shared key is KDF(DH1||DH2||DH3||DH4)
        self.__sk = Libutils.hkdf(dh1 + dh2 + dh3 + dh4, 32)
        # print('[Receiver]\tShared key:', Libutils.b64(self.__sk))

    def start_dh_ratchet(self, recipient):
        # perform a DH ratchet rotation using Alice's public key
        dh_recv = self.__DHratchet.exchange(recipient)
        shared_recv = self.__root_ratchet.next(dh_recv)[0]
        # use Alice's public and our old private key
        # to get a new recv ratchet
        self.__recv_ratchet = SymmRatchet(shared_recv)
        # print('[Bob]\tRecv ratchet seed:', Libutils.b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Alice
        self.__DHratchet = X25519PrivateKey.generate()
        dh_send = self.__DHratchet.exchange(recipient)
        shared_send = self.__root_ratchet.next(dh_send)[0]
        self.__send_ratchet = SymmRatchet(shared_send)
        print('[recipient]\tSend ratchet seed:', Libutils.b64(shared_send))

    def respond_dh_ratchet(self, sender: object):
        # perform a DH ratchet rotation using Bob's public key
        if self.__DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = self.__DHratchet.exchange(sender)
            shared_recv = self.__root_ratchet.next(dh_recv)[0]
            # use Bob's public and our old private key
            # to get a new recv ratchet
            self.__recv_ratchet = SymmRatchet(shared_recv)
            # print('[Alice]\tRecv ratchet seed:', Libutils.b64(shared_recv))
        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.__DHratchet = X25519PrivateKey.generate()
        dh_send = self.__DHratchet.exchange(sender)
        shared_send = self.__root_ratchet.next(dh_send)[0]
        self.__send_ratchet = SymmRatchet(shared_send)
        # print('[Alice]\tSend ratchet seed:', Libutils.b64(shared_send))

    def send(self, msg):
        key, iv = self.__send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(Libutils.pad(msg))
        # print(f'[{self.__name}]\tSending ciphertext to recipient:', Libutils.b64(cipher))
        # send ciphertext and current DH public key
        return cipher, self.__DHratchet.public_key()

    def recv(self, cipher, sender_pk):
        # receive Bob's new public key and use it to perform a DH
        self.respond_dh_ratchet(sender_pk)
        key, iv = self.__recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = Libutils.unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print(f'[]\tDecrypted message:', msg)


def listen_server(conn: socket.socket):
    while True:
        data = conn.recv(1024)
        info = json.loads(data.decode("utf8"))
        if info["command"] == "ratchet":
            pass
        print(data)


def command(conn: socket.socket):
    prepare = {}
    command = input("Inserte un commando: ")
    if command == "enviar":
        prepare["recipient"] = input("usuario: ")
        prepare["message"] = input("Message: ")
    if command == "connect":
        prepare["recipient"] = input("usuario: ")
        conn.send(json.dumps(prepare).encode("utf8"))

if __name__ == "__main__":

    bob = User("bob")
    bobKeys = bob.keys_to_server()

    alice = User("alice")
    alice.start_x3dh(bobKeys)

    # aliceKeysPrepared = alice.keys_prepared_send()
    aliceKeys = alice.keys_to_server()

    bob.responding_x3dh(aliceKeys)

    alice.init_ratchets()
    bobDHPublic = bob.get_DHpublic()
    bob.init_ratchets()
    identifier = None
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        with ThreadPoolExecutor(max_workers=2) as executor:
            s.connect((HOST, PORT))  # Iniciar el socket
            executor.submit(listen_server)
            s.sendall(aliceKeysPrepared)  # Enviar mensaje en formato binario
            # data = s.recv(1024)  # Recibir respuesta
            command(s)
            # print('Received', repr(data))  # imprimir respuesta
            s.shutdown(0)
            data = s.recv(1024)  # Recibir respuesta
            if data == '':
                s.close()
    """

    alice.respond_dh_ratchet(bobDHPublic)

    # Alice sends Bob a message and her new DH ratchet public key
    cipher, ratchet_k = alice.send('Hello Bob!'.encode("utf8"))

    bob.recv(cipher, ratchet_k)
    # Bob uses that information to sync with Alice and send her a message
    cipher, ratchet_k = bob.send('Hello to you too, Alice!'.encode("utf8"))

    alice.recv(cipher, ratchet_k)
    # alice.send(bob, "hola".encode("utf8"))
    """
    Printing keys 
    print('[Alice]\tsend ratchet:', list(map(Libutils.b64, alice.next_send())))
    print('[Bob]\trecv ratchet:', list(map(Libutils.b64, bob.next_recv())))
    print('[Alice]\trecv ratchet:', list(map(Libutils.b64, alice.next_recv())))
    print('[Bob]\tsend ratchet:', list(map(Libutils.b64, bob.next_send())))
    """
