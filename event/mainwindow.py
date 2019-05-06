from PySide2.QtWidgets import QMainWindow
from ui.mainwindow import Ui_MainWindow
from PySide2.QtWidgets import QFileDialog, QMessageBox
from core.communication import ASender, BListener
from core.encryption import msg_encode, msg_decode
import config as cfg
import logging
from tools import encutils


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.MD5.toggled.connect(self.MD5_Checked)
        self.SHA.toggled.connect(self.SHA_Checked)
        self.DES.toggled.connect(self.DES_Checked)
        self.AES.toggled.connect(self.AES_Checked)
        self.DES_AES_Key_Editor.editingFinished.connect(self.DES_AES_KEY_PATH_Editor_finished)
        self.RSA_A_Pri_Editor.editingFinished.connect(self.RSA_A_PRI_PATH_Editor_finished)
        self.RSA_B_Pub_Editor.editingFinished.connect(self.RSA_B_PUB_PATH_Editor_finished)
        self.RSA_A_Pri_Sel_Button.clicked.connect(self.RSA_A_PRI_KEY_select)
        self.RSA_B_Pub_Sel_Button.clicked.connect(self.RSA_B_PUB_KEY_select)
        self.AES_DES_Key_Sel_Button.clicked.connect(self.DES_AES_KEY_select)
        self.RSA_B_Pri_Sel_Button.clicked.connect(self.RSA_B_PRI_KEY_select)
        self.RSA_B_Pri_Editor.editingFinished.connect(self.RSA_B_PRI_PATH_Editor_finished)
        self.RSA_A_PUB_Sel_Button.clicked.connect(self.RSA_A_PUB_KEY_select)
        self.RSA_A_Pub_Editor.editingFinished.connect(self.RSA_A_PUB_PATH_Editor_finished)
        self.Button_Generate_Aes_key.clicked.connect(self.generate_aes_key)
        self.Button_Generate_DES_Key.clicked.connect(self.generate_des_key)
        self.Button_Generate_RSA_Key.clicked.connect(self.generate_rsa_key_pair)
        self.action_generate_des_key.triggered.connect(self.generate_des_key)
        self.action_generate_aes_key.triggered.connect(self.generate_aes_key)
        self.action_generate_rsa_key.triggered.connect(self.generate_rsa_key_pair)
        self.blistener = BListener(cfg.PORT,  msg_decode, self.B_Msg_Recv, cfg.IP)
        self.blistener.start()
        self.A_SendMsg_button.clicked.connect(self.A_Msg_Send)
        self.set_init_properties()

    def set_init_properties(self):
        self.symEncMethod = 'DES'
        self.hashFunction = 'MD5'
        self.A_box.RSA_A_PRI_PATH = ''
        self.A_box.RSA_B_PUB_PATH = ''
        self.A_box.AES_DES_KEY_PATH = ''
        self.B_box.RSA_B_PRI_PATH = ''
        self.B_box.RSA_A_PUB_PATH = ''
        self.blistener.HASH_FUNCTION = 'MD5'
        self.blistener.SYM_ENC_METHOD = 'DES'
        self.blistener.RSA_B_PRI_PATH = ''
        self.blistener.RSA_A_PUB_PATH = ''

    # Menu bar event
    def generate_des_key(self):
        # TODO. Random or Random seed.
        fdiag = QFileDialog(self, '~', '生成DES密钥')
        fdiag.setFileMode(QFileDialog.AnyFile)
        fdiag.setAcceptMode(QFileDialog.AcceptSave)
        fdiag.setConfirmOverwrite(True)
        if fdiag.exec_():
            des_key_path = fdiag.selectedFiles()[0]
            encutils.generate_des_key(des_key_path)
            logging.info('generate DES key.(Key Path :{})'.format(des_key_path))

    def generate_aes_key(self):
        # TODO. Random or Random seed.
        fdiag = QFileDialog(self, '~', '生成AES密钥')
        fdiag.setFileMode(QFileDialog.AnyFile)
        fdiag.setAcceptMode(QFileDialog.AcceptSave)
        fdiag.setConfirmOverwrite(True)
        if fdiag.exec_():
            aes_key_path = fdiag.selectedFiles()[0]
            encutils.generate_aes_key(aes_key_path)
            logging.info('generate AES key.(Key Path :{})'.format(aes_key_path))

    def generate_rsa_key_pair(self):
        # TODO. Random or Random seed.
        fdiag = QFileDialog(self, '~', '生成RSA公钥和密钥')
        fdiag.setFileMode(QFileDialog.Directory)
        fdiag.setConfirmOverwrite(True)
        if fdiag.exec_():
            rsa_key_path = fdiag.selectedFiles()[0]
            encutils.generate_rsa_key_pair(rsa_key_path)
            logging.info('generate DES/AES key.(Key Path :{})'.format(rsa_key_path))

    def MD5_Checked(self, state):
        logging.info('MD5 button state changed to {}'.format(state))
        if state:
            self.hashFunction = 'MD5'
            self.SHA.setChecked(False)
            self.blistener.HASH_FUNCTION = self.hashFunction

    def SHA_Checked(self, state):
        logging.info('SHA button state changed to {}'.format(state))
        if state:
            self.hashFunction = 'SHA'
            self.MD5.setChecked(False)
            self.blistener.HASH_FUNCTION = self.hashFunction

    def DES_Checked(self, state):
        logging.info('DES button state changed to {}'.format(state))
        if state:
            self.symEncMethod = 'DES'
            self.DES_AES_Label.setText('DES密钥    :')
            self.AES.setChecked(False)
            self.blistener.SYM_ENC_METHOD = self.symEncMethod

    def AES_Checked(self, state):
        logging.info('AES button state changed to {}'.format(state))
        if state:
            self.symEncMethod = 'AES'
            self.DES_AES_Label.setText('DES密钥    :')
            self.DES.setChecked(False)
            self.blistener.SYM_ENC_METHOD = self.symEncMethod


    # Logic of A
    def DES_AES_KEY_PATH_Editor_finished(self):
        des_aes_key_path = self.DES_AES_Key_Editor.text()
        logging.info('AES/DES key path edit finished.(Path is {})'.format(des_aes_key_path))
        self.A_box.AES_DES_KEY_PATH = des_aes_key_path

    def DES_AES_KEY_select(self):
        fdiag = QFileDialog(self, '~', '选择A的RSA私钥')
        fdiag.setFileMode(QFileDialog.ExistingFile)
        if fdiag.exec_():
            des_aes_key_path = fdiag.selectedFiles()[0]
            logging.info('Select DES/AES key.(Key Path :{})'.format(des_aes_key_path))
            self.DES_AES_Key_Editor.setText(des_aes_key_path)
            self.A_box.AES_DES_KEY_PATH = des_aes_key_path

    def RSA_A_PRI_PATH_Editor_finished(self):
        rsa_a_pri_path = self.RSA_A_Pri_Editor.text()
        logging.info('RSA_A_pri key path edit finished.(Path is {})'.format(rsa_a_pri_path))
        self.A_box.RSA_A_PRI_PATH = rsa_a_pri_path

    def RSA_A_PRI_KEY_select(self):
        fdiag = QFileDialog(self, '~', '选择A的RSA私钥')
        fdiag.setFileMode(QFileDialog.ExistingFile)
        if fdiag.exec_():
            rsa_a_pri_path = fdiag.selectedFiles()[0]
            logging.info('Select Private rsa key of a.(Key Path :{})'.format(rsa_a_pri_path))
            self.RSA_A_Pri_Editor.setText(rsa_a_pri_path)
            self.A_box.RSA_A_PRI_PATH = rsa_a_pri_path

    def RSA_B_PUB_PATH_Editor_finished(self):
        rsa_b_pub_path = self.RSA_B_Pub_Editor.text()
        logging.info('RSA_B_pub key path edit finished.(Path is {})'.format(rsa_b_pub_path))
        self.A_box.RSA_B_PUB_PATH = rsa_b_pub_path

    def RSA_B_PUB_KEY_select(self):
        fdiag = QFileDialog(self, '~', '选择B的RSA公钥')
        fdiag.setFileMode(QFileDialog.ExistingFile)
        if fdiag.exec_():
            rsa_b_pub_path = fdiag.selectedFiles()[0]
            logging.info('Select Public rsa key of b.(Key Path :{})'.format(rsa_b_pub_path))
            self.RSA_B_Pub_Editor.setText(rsa_b_pub_path)
            self.A_box.RSA_B_PUB_PATH = rsa_b_pub_path

    def A_Msg_Send(self):
        # check msg
        msg = self.message_editor.toPlainText()
        if len(msg) <= 0:
            msgbox = QMessageBox()
            msgbox.setText("请输入内容后再选择发送。")
            msgbox.exec_()
        else:
            if not encutils.valid_aes_des_key(self.symEncMethod, self.A_box.AES_DES_KEY_PATH) or \
                    not encutils.valid_rsa_key(self.A_box.RSA_A_PRI_PATH) or \
                    not encutils.valid_rsa_key(self.A_box.RSA_B_PUB_PATH) or \
                    not encutils.valid_rsa_key(self.B_box.RSA_B_PRI_PATH) or \
                    not encutils.valid_rsa_key(self.B_box.RSA_A_PUB_PATH):
                QMessageBox(text='请选择正确的秘钥，如果没有秘钥，请在菜单栏中生成。').exec_()
            else:
                self.setEnabled(False)

                enc_structure = {
                    'SYM_ENC_METHOD': self.symEncMethod,
                    'HASH_FUNCTION': self.hashFunction,
                    'AES_DES_KEY_PATH' : self.A_box.AES_DES_KEY_PATH,
                    'RSA_A_PRI_PATH' : self.A_box.RSA_A_PRI_PATH,
                    'RSA_B_PUB_PATH' : self.A_box.RSA_B_PUB_PATH
                }
                logging.info('encode with enc_structure:{}'.format(enc_structure))
                sender = ASender(msg, msg_encode, enc_structure, cfg.PORT, cfg.IP)
                sender.send_finished.connect(self.Msg_Send_Finished)
                sender.start()

    def Msg_Send_Finished(self):
        mb = QMessageBox()
        mb.setText('信息发送成功。')
        mb.exec_()


    # Logic of B
    def RSA_A_PUB_PATH_Editor_finished(self):
        rsa_a_pub_path = self.RSA_A_Pub_Editor.text()
        logging.info('RSA_B_pub key path edit finished.(Path is {})'.format(rsa_a_pub_path))
        self.B_box.RSA_A_PUB_PATH = rsa_a_pub_path
        self.blistener.RSA_A_PUB_PATH = rsa_a_pub_path

    def RSA_A_PUB_KEY_select(self):
        fdiag = QFileDialog(self, '~', '选择A的RSA公钥')
        fdiag.setFileMode(QFileDialog.ExistingFile)
        if fdiag.exec_():
            rsa_a_pub_path = fdiag.selectedFiles()[0]
            logging.info('Select Private rsa key of a.(Key Path :{})'.format(rsa_a_pub_path))
            self.RSA_A_Pub_Editor.setText(rsa_a_pub_path)
            self.B_box.RSA_A_Pub_PATH = rsa_a_pub_path
            self.blistener.RSA_A_PUB_PATH = rsa_a_pub_path

    def RSA_B_PRI_PATH_Editor_finished(self):
        rsa_b_pri_path = self.RSA_B_Pri_Editor.text()
        logging.info('RSA_B_pri key path edit finished.(Path is {})'.format(rsa_b_pri_path))
        self.B_box.RSA_B_PRI_PATH = rsa_b_pri_path
        self.blistener.RSA_B_PRI_PATH = rsa_b_pri_path

    def RSA_B_PRI_KEY_select(self):
        fdiag = QFileDialog(self, '~', '选择B的RSA私钥')
        fdiag.setFileMode(QFileDialog.ExistingFile)
        if fdiag.exec_():
            rsa_b_pri_path = fdiag.selectedFiles()[0]
            logging.info('Select Private rsa key of b.(Key Path :{})'.format(rsa_b_pri_path))
            self.RSA_B_Pri_Editor.setText(rsa_b_pri_path)
            self.B_box.RSA_B_PRI_PATH = rsa_b_pri_path
            self.blistener.RSA_B_PRI_PATH = rsa_b_pri_path

    def B_Msg_Recv(self, cooked_data):
        msg, transfered_hash, hash = cooked_data
        self.B_messagebox.setText(msg)
        self.Hash_R.setText(transfered_hash)
        self.Hash_C.setText(hash)
        self.setEnabled(True)