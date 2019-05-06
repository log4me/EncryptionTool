import config
import Cryptodome.Random as Random
from Cryptodome.PublicKey import RSA
import os
def valid_aes_des_key(method, path):
    return True


def valid_rsa_key(path):
    return True

def generate_des_key(path):
    key = Random.get_random_bytes(config.DES_KEY_LENGTH // 8)
    with open(path, 'wb') as f:
        f.write(key)

def generate_aes_key(path):
    key = Random.get_random_bytes(config.AES_KEY_LENGTH // 8)
    with open(path, 'wb') as f:
        f.write(key)

def generate_rsa_key_pair(path):
    random_generator = Random.new().read
    rsa = RSA.generate(config.RSA_KEY_LENGTH, random_generator)
    with open(os.path.join(path, 'id_rsa.pem'), 'wb') as f:
        f.write(rsa.export_key())
    with open(os.path.join(path, 'id_rsa.pub.pem'), 'wb') as f:
        f.write(rsa.publickey().export_key())

