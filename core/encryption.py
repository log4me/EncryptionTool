from Cryptodome.Hash import MD5, SHA3_512
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES, DES
from tools import byteutils
import binascii
import config
import os
def msg_encode(msg, enc_structure):
    msg = msg.encode()
    if enc_structure['HASH_FUNCTION'] == 'MD5':
        hash_object = MD5.new()
    elif enc_structure['HASH_FUNCTION'] == 'SHA':
        hash_object = SHA3_512.new()
    else:
        raise NotImplementedError('No Such Hash Function({}).'.format(enc_structure['HASH_FUNCTION']))

    assert os.path.exists(enc_structure['AES_DES_KEY_PATH'])
    with open(enc_structure['AES_DES_KEY_PATH'], 'rb') as f:
        key_aes_des = f.read()

    assert os.path.exists(enc_structure['RSA_A_PRI_PATH'])
    with open(enc_structure['RSA_A_PRI_PATH'], 'rb') as f:
        key_rsa_a_pri = f.read()

    assert os.path.exists(enc_structure['RSA_B_PUB_PATH'])
    with open(enc_structure['RSA_B_PUB_PATH'], 'rb') as f:
        key_rsa_b_pub = f.read()

    if enc_structure['SYM_ENC_METHOD'] == 'DES':
        blocksize = 8
        cipher_aes_des = DES.new(key_aes_des, DES.MODE_ECB)
    elif enc_structure['SYM_ENC_METHOD'] == 'AES':
        blocksize = 16
        cipher_aes_des = AES.new(key_aes_des, AES.MODE_ECB)
    else:
        raise NotImplementedError('No Such symmetry encrypte Method.({})'.format(enc_structure['SYM_ENC_METHOD']))
    hash_object.update(msg)

    RK_A = RSA.import_key(key_rsa_a_pri)
    ciper_rsa_a = pkcs1_15.new(RK_A)

    UK_B = RSA.import_key(key_rsa_b_pub)
    ciper_rsa_b = PKCS1_OAEP.new(UK_B)

    # 加密Hash值 TODO. 加密 OR 签名
    hash_signature = ciper_rsa_a.sign(hash_object)
    data_signature_len = byteutils.int_to_bytes(len(hash_signature), config.HASH_LENGTH_COUNTER_LENGTH)

    # 拼接签名后的Hash值和消息
    data_hash_len_hash_msg = data_signature_len + hash_signature + msg

    # 使用AES/DES密钥加密msg和hash值
    encrypted_signature_len_signature_msg = cipher_aes_des.encrypt(pad(data_hash_len_hash_msg, blocksize))
    data_hash_msg_len = byteutils.int_to_bytes(len(encrypted_signature_len_signature_msg), config.MSG_HASH_LENGTH_COUNTER_LENGTH)

    # 使用RSA加密AES/DES密钥
    encrypted_aes_des_key = ciper_rsa_b.encrypt(key_aes_des)

    # 拼接 msg, hash, key
    cooked_data = data_hash_msg_len + encrypted_signature_len_signature_msg + encrypted_aes_des_key

    return cooked_data

def msg_decode(encrypted_data, dec_structure):
    hash_msg_len_data, data_hash_len_hash_msg_key = encrypted_data[0:config.MSG_HASH_LENGTH_COUNTER_LENGTH], encrypted_data[config.MSG_HASH_LENGTH_COUNTER_LENGTH:]
    hash_msg_len = byteutils.bytes_to_int(hash_msg_len_data)
    # encrypted_signature_len_signature_msg is encrypted by aes_des_key
    encrypted_signature_len_signature_msg, encrypted_aes_des_key = data_hash_len_hash_msg_key[0:hash_msg_len], data_hash_len_hash_msg_key[hash_msg_len:]
    assert os.path.exists(dec_structure['RSA_B_PRI_PATH'])
    with open(dec_structure['RSA_B_PRI_PATH'], 'rb') as f:
        rsa_b_pri_key = f.read()

    assert os.path.exists(dec_structure['RSA_A_PUB_PATH'])
    with open(dec_structure['RSA_A_PUB_PATH'], 'rb') as f:
        rsa_a_pub_key = f.read()
    RK_B = RSA.import_key(rsa_b_pri_key)
    ciper_rsa_b = PKCS1_OAEP.new(RK_B)

    UK_A = RSA.import_key(rsa_a_pub_key)
    ciper_rsa_a = pkcs1_15.new(UK_A)

    aes_des_key = ciper_rsa_b.decrypt(encrypted_aes_des_key)
    if dec_structure['SYM_ENC_METHOD'] == 'DES':
        blocksize = 8
        cipher_aes_des = DES.new(aes_des_key, DES.MODE_ECB)
    elif dec_structure['SYM_ENC_METHOD'] == 'AES':
        blocksize = 16
        cipher_aes_des = AES.new(aes_des_key, AES.MODE_ECB)
    else:
        raise NotImplementedError('No Such symmetry encrypte Method.({})'.format(dec_structure['SYM_ENC_METHOD']))
    data_signature_len_signature_msg = unpad(cipher_aes_des.decrypt(encrypted_signature_len_signature_msg), blocksize)
    data_signature_len, data_signature_msg = data_signature_len_signature_msg[0: config.HASH_LENGTH_COUNTER_LENGTH], data_signature_len_signature_msg[config.HASH_LENGTH_COUNTER_LENGTH:]
    hash_len = byteutils.bytes_to_int(data_signature_len)
    signature_hash, msg = data_signature_msg[0: hash_len], data_signature_msg[hash_len:]

    if dec_structure['HASH_FUNCTION'] == 'MD5':
        hash_object = MD5.new()
    elif dec_structure['HASH_FUNCTION'] == 'SHA':
        hash_object = SHA3_512.new()
    else:
        raise NotImplementedError('No Such Hash Function({}).'.format(dec_structure['HASH_FUNCTION']))
    hash_object.update(msg)
    hash = hash_object.digest()
    try:
        ciper_rsa_a.verify(hash_object, signature_hash)
        signature_check_result = 'HASH签名验证通过。'
    except Exception as e:
        signature_check_result = 'HASH签名验证不通过。'
    hash = binascii.b2a_hex(hash).decode()
    msg = msg.decode()
    return msg, signature_check_result, hash