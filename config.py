import logging
logging.basicConfig(filename='app.log',level=logging.DEBUG,format='%(asctime)s %(filename)s[line:%(lineno)d] %(message)s',datefmt='%Y-%m-%d')
PORT=10800
IP="127.0.0.1"
AES_KEY_LENGTH = 256
DES_KEY_LENGTH = 64
RSA_KEY_LENGTH = 2048
HASH_LENGTH_COUNTER_LENGTH = 4
MSG_HASH_LENGTH_COUNTER_LENGTH = 8