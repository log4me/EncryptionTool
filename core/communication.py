import config
import socket
import tools.byteutils as bu
try :
    from PySide2.QtCore import Signal, QObject
except ModuleNotFoundError:
    from PyQt5.QtCore import pyqtSignal as Signal
    from PyQt5.QtCore import QObject
import threading
import logging


class BListener(threading.Thread, QObject):

    def __init__(self, port, received_callback, update_ui, bind_addr='127.0.0.1'):
        threading.Thread.__init__(self)
        QObject.__init__(self)
        self.setDaemon(True)
        self.received_callback = received_callback
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_addr, port))
        self.sock.listen(1)
        self.update_ui = update_ui
        logging.info('Listening on {}:{}'.format(bind_addr, port))

    def run(self):
        while True:
            client, addr = self.sock.accept()
            decode_structure = {
                'RSA_B_PRI_PATH' : self.RSA_B_PRI_PATH,
                'RSA_A_PUB_PATH' : self.RSA_A_PUB_PATH,
                'HASH_FUNCTION' : self.HASH_FUNCTION,
                'SYM_ENC_METHOD' : self.SYM_ENC_METHOD
            }
            reader = BReader(client, received_callback=self.received_callback, decode_structure=decode_structure)
            reader.recv_finished.connect(self.update_ui)
            reader.start()
            logging.info('Accept connection from {}.'.format(addr))


class BReader(QObject, threading.Thread):
    recv_finished = Signal(tuple)
    def __init__(self, client, received_callback, decode_structure, BUFSIZE=1024):
        QObject.__init__(self)
        threading.Thread.__init__(self)
        self.client = client
        self.BUFSIZE = BUFSIZE
        self.received_data = b''
        self.counter_size = 4
        self.counter = b''
        self.received_callback = received_callback
        self.decode_structure = decode_structure
    def run(self):
        received_size = 0
        while received_size < self.counter_size:
            data = self.client.recv(self.counter_size - received_size)
            if data:
                received_size += len(data)
                self.counter += data
            else:
                break
        if received_size >= self.counter_size:
            self.counter = bu.bytes_to_int(self.counter)
            logging.info('Msg Size :{}'.format(self.counter))
            received_size = 0
            while received_size < self.counter:
                TBUFSIZE = min(self.counter - received_size, self.BUFSIZE)
                data = self.client.recv(TBUFSIZE)
                if data:
                    received_size += len(data)
                    self.received_data += data
                else:
                    break
            self.client.close()
            if received_size < self.counter:
                logging.warning('Received Msg size({}) is small than reported size({}), some error occured.'.format(received_size, self.counter))
                cooked_data = self.received_callback(self.received_data, self.decode_structure)
                self.recv_finished.emit(cooked_data)
            else:
                logging.info('Received Msg of size {}.'.format(received_size))
                cooked_data = self.received_callback(self.received_data, self.decode_structure)
                self.recv_finished.emit(cooked_data)


class ASender(threading.Thread, QObject):
    send_finished = Signal()
    def __init__(self, data, data_encode_func, encode_structure, port, ip):
        threading.Thread.__init__(self)
        QObject.__init__(self)
        self.data = data
        self.data_encode_func = data_encode_func
        self.encode_structure = encode_structure
        self.port = port
        self.ip = ip
        self.counter_size = 4

    def run(self):
        data = self.data_encode_func(self.data, self.encode_structure)
        client = socket.socket()
        client.connect((self.ip, self.port))
        counter = len(data)
        counter_data = bu.int_to_bytes(counter, self.counter_size)
        client.send(counter_data)
        client.send(data)
        client.close()
        self.send_finished.emit()

def simple_process_func(data):
    return data.encode()


if __name__ == '__main__':
    lst = BListener(6666, print)
    lst.start()
    A = ASender('abcdefg', simple_process_func, print, 6666, '127.0.0.1')
    A.start()
