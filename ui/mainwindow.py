# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\mainwindow.ui',
# licensing of '.\mainwindow.ui' applies.
#
# Created: Mon May  6 11:19:46 2019
#      by: pyside2-uic  running on PySide2 5.12.3
#
# WARNING! All changes made in this file will be lost!

from PySide2 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setEnabled(True)
        MainWindow.resize(989, 822)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QtCore.QSize(0, 0))
        MainWindow.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_16 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_16.setObjectName("verticalLayout_16")
        self.frame_11 = QtWidgets.QFrame(self.centralwidget)
        self.frame_11.setMinimumSize(QtCore.QSize(971, 591))
        self.frame_11.setStyleSheet("font: 12pt;")
        self.frame_11.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_11.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_11.setObjectName("frame_11")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(self.frame_11)
        self.horizontalLayout_7.setSpacing(0)
        self.horizontalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.A_box = QtWidgets.QGroupBox(self.frame_11)
        self.A_box.setObjectName("A_box")
        self.verticalLayout_9 = QtWidgets.QVBoxLayout(self.A_box)
        self.verticalLayout_9.setSpacing(0)
        self.verticalLayout_9.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_9.setObjectName("verticalLayout_9")
        self.groupBox = QtWidgets.QGroupBox(self.A_box)
        self.groupBox.setObjectName("groupBox")
        self.verticalLayout_10 = QtWidgets.QVBoxLayout(self.groupBox)
        self.verticalLayout_10.setSpacing(0)
        self.verticalLayout_10.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_10.setObjectName("verticalLayout_10")
        self.message_editor = QtWidgets.QPlainTextEdit(self.groupBox)
        self.message_editor.setEnabled(True)
        self.message_editor.setDocumentTitle("")
        self.message_editor.setPlainText("")
        self.message_editor.setObjectName("message_editor")
        self.verticalLayout_10.addWidget(self.message_editor)
        self.frame_7 = QtWidgets.QFrame(self.groupBox)
        self.frame_7.setAutoFillBackground(False)
        self.frame_7.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_7.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_7.setObjectName("frame_7")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self.frame_7)
        self.horizontalLayout_4.setSpacing(6)
        self.horizontalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.frame_6 = QtWidgets.QFrame(self.frame_7)
        self.frame_6.setMaximumSize(QtCore.QSize(170, 16777215))
        self.frame_6.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_6.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_6.setObjectName("frame_6")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.frame_6)
        self.verticalLayout_6.setSpacing(0)
        self.verticalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.Hash_function_selection = QtWidgets.QGroupBox(self.frame_6)
        self.Hash_function_selection.setObjectName("Hash_function_selection")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.Hash_function_selection)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.frame_5 = QtWidgets.QFrame(self.Hash_function_selection)
        self.frame_5.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_5.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_5.setObjectName("frame_5")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.frame_5)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.MD5 = QtWidgets.QRadioButton(self.frame_5)
        self.MD5.setChecked(True)
        self.MD5.setObjectName("MD5")
        self.verticalLayout_4.addWidget(self.MD5)
        self.SHA = QtWidgets.QRadioButton(self.frame_5)
        self.SHA.setChecked(False)
        self.SHA.setObjectName("SHA")
        self.verticalLayout_4.addWidget(self.SHA)
        self.verticalLayout_5.addWidget(self.frame_5)
        self.verticalLayout_6.addWidget(self.Hash_function_selection)
        self.sym_encryption_selection = QtWidgets.QGroupBox(self.frame_6)
        self.sym_encryption_selection.setObjectName("sym_encryption_selection")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.sym_encryption_selection)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.frame_4 = QtWidgets.QFrame(self.sym_encryption_selection)
        self.frame_4.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_4.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_4.setObjectName("frame_4")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.frame_4)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.DES = QtWidgets.QRadioButton(self.frame_4)
        self.DES.setChecked(True)
        self.DES.setObjectName("DES")
        self.verticalLayout_3.addWidget(self.DES)
        self.AES = QtWidgets.QRadioButton(self.frame_4)
        self.AES.setObjectName("AES")
        self.verticalLayout_3.addWidget(self.AES)
        self.verticalLayout_2.addWidget(self.frame_4)
        self.verticalLayout_6.addWidget(self.sym_encryption_selection)
        self.horizontalLayout_4.addWidget(self.frame_6)
        self.key_selection = QtWidgets.QGroupBox(self.frame_7)
        self.key_selection.setObjectName("key_selection")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.key_selection)
        self.verticalLayout.setSpacing(1)
        self.verticalLayout.setObjectName("verticalLayout")
        self.frame_3 = QtWidgets.QFrame(self.key_selection)
        self.frame_3.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_3.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_3.setObjectName("frame_3")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.frame_3)
        self.horizontalLayout_2.setSpacing(6)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.RSA_A_Pri_Label = QtWidgets.QLabel(self.frame_3)
        self.RSA_A_Pri_Label.setStyleSheet("font: 12pt;")
        self.RSA_A_Pri_Label.setObjectName("RSA_A_Pri_Label")
        self.horizontalLayout_2.addWidget(self.RSA_A_Pri_Label)
        self.RSA_A_Pri_Editor = QtWidgets.QLineEdit(self.frame_3)
        self.RSA_A_Pri_Editor.setMinimumSize(QtCore.QSize(70, 0))
        self.RSA_A_Pri_Editor.setObjectName("RSA_A_Pri_Editor")
        self.horizontalLayout_2.addWidget(self.RSA_A_Pri_Editor)
        self.RSA_A_Pri_Sel_Button = QtWidgets.QToolButton(self.frame_3)
        self.RSA_A_Pri_Sel_Button.setObjectName("RSA_A_Pri_Sel_Button")
        self.horizontalLayout_2.addWidget(self.RSA_A_Pri_Sel_Button)
        self.verticalLayout.addWidget(self.frame_3)
        self.frame_2 = QtWidgets.QFrame(self.key_selection)
        self.frame_2.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_2.setObjectName("frame_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.frame_2)
        self.horizontalLayout.setSpacing(6)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.RSA_B_Pub_Label = QtWidgets.QLabel(self.frame_2)
        self.RSA_B_Pub_Label.setObjectName("RSA_B_Pub_Label")
        self.horizontalLayout.addWidget(self.RSA_B_Pub_Label)
        self.RSA_B_Pub_Editor = QtWidgets.QLineEdit(self.frame_2)
        self.RSA_B_Pub_Editor.setMinimumSize(QtCore.QSize(70, 0))
        self.RSA_B_Pub_Editor.setObjectName("RSA_B_Pub_Editor")
        self.horizontalLayout.addWidget(self.RSA_B_Pub_Editor)
        self.RSA_B_Pub_Sel_Button = QtWidgets.QToolButton(self.frame_2)
        self.RSA_B_Pub_Sel_Button.setObjectName("RSA_B_Pub_Sel_Button")
        self.horizontalLayout.addWidget(self.RSA_B_Pub_Sel_Button)
        self.verticalLayout.addWidget(self.frame_2)
        self.frame = QtWidgets.QFrame(self.key_selection)
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.frame)
        self.horizontalLayout_3.setSpacing(6)
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.DES_AES_Label = QtWidgets.QLabel(self.frame)
        self.DES_AES_Label.setObjectName("DES_AES_Label")
        self.horizontalLayout_3.addWidget(self.DES_AES_Label)
        self.DES_AES_Key_Editor = QtWidgets.QLineEdit(self.frame)
        self.DES_AES_Key_Editor.setMinimumSize(QtCore.QSize(70, 0))
        self.DES_AES_Key_Editor.setObjectName("DES_AES_Key_Editor")
        self.horizontalLayout_3.addWidget(self.DES_AES_Key_Editor)
        self.AES_DES_Key_Sel_Button = QtWidgets.QToolButton(self.frame)
        self.AES_DES_Key_Sel_Button.setObjectName("AES_DES_Key_Sel_Button")
        self.horizontalLayout_3.addWidget(self.AES_DES_Key_Sel_Button)
        self.verticalLayout.addWidget(self.frame)
        self.horizontalLayout_4.addWidget(self.key_selection)
        self.frame_8 = QtWidgets.QFrame(self.frame_7)
        self.frame_8.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_8.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_8.setObjectName("frame_8")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.frame_8)
        self.verticalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.groupBox_8 = QtWidgets.QGroupBox(self.frame_8)
        self.groupBox_8.setObjectName("groupBox_8")
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.groupBox_8)
        self.verticalLayout_8.setSpacing(0)
        self.verticalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.Button_Generate_DES_Key = QtWidgets.QPushButton(self.groupBox_8)
        self.Button_Generate_DES_Key.setObjectName("Button_Generate_DES_Key")
        self.verticalLayout_8.addWidget(self.Button_Generate_DES_Key)
        self.Button_Generate_Aes_key = QtWidgets.QPushButton(self.groupBox_8)
        self.Button_Generate_Aes_key.setObjectName("Button_Generate_Aes_key")
        self.verticalLayout_8.addWidget(self.Button_Generate_Aes_key)
        self.Button_Generate_RSA_Key = QtWidgets.QPushButton(self.groupBox_8)
        self.Button_Generate_RSA_Key.setObjectName("Button_Generate_RSA_Key")
        self.verticalLayout_8.addWidget(self.Button_Generate_RSA_Key)
        self.verticalLayout_7.addWidget(self.groupBox_8)
        self.A_SendMsg_button = QtWidgets.QPushButton(self.frame_8)
        self.A_SendMsg_button.setObjectName("A_SendMsg_button")
        self.verticalLayout_7.addWidget(self.A_SendMsg_button)
        self.horizontalLayout_4.addWidget(self.frame_8)
        self.verticalLayout_10.addWidget(self.frame_7)
        self.verticalLayout_9.addWidget(self.groupBox)
        self.horizontalLayout_7.addWidget(self.A_box)
        self.line = QtWidgets.QFrame(self.frame_11)
        self.line.setEnabled(True)
        self.line.setFrameShape(QtWidgets.QFrame.VLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.horizontalLayout_7.addWidget(self.line)
        self.B_box = QtWidgets.QGroupBox(self.frame_11)
        self.B_box.setObjectName("B_box")
        self.verticalLayout_15 = QtWidgets.QVBoxLayout(self.B_box)
        self.verticalLayout_15.setSpacing(0)
        self.verticalLayout_15.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_15.setObjectName("verticalLayout_15")
        self.groupBox_15 = QtWidgets.QGroupBox(self.B_box)
        self.groupBox_15.setObjectName("groupBox_15")
        self.verticalLayout_14 = QtWidgets.QVBoxLayout(self.groupBox_15)
        self.verticalLayout_14.setSpacing(0)
        self.verticalLayout_14.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_14.setObjectName("verticalLayout_14")
        self.B_messagebox = QtWidgets.QTextBrowser(self.groupBox_15)
        self.B_messagebox.setObjectName("B_messagebox")
        self.verticalLayout_14.addWidget(self.B_messagebox)
        self.verticalLayout_15.addWidget(self.groupBox_15)
        self.groupBox_17 = QtWidgets.QGroupBox(self.B_box)
        self.groupBox_17.setObjectName("groupBox_17")
        self.verticalLayout_13 = QtWidgets.QVBoxLayout(self.groupBox_17)
        self.verticalLayout_13.setSpacing(0)
        self.verticalLayout_13.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_13.setObjectName("verticalLayout_13")
        self.Hash_C = QtWidgets.QTextBrowser(self.groupBox_17)
        self.Hash_C.setObjectName("Hash_C")
        self.verticalLayout_13.addWidget(self.Hash_C)
        self.verticalLayout_15.addWidget(self.groupBox_17)
        self.groupBox_16 = QtWidgets.QGroupBox(self.B_box)
        self.groupBox_16.setObjectName("groupBox_16")
        self.verticalLayout_12 = QtWidgets.QVBoxLayout(self.groupBox_16)
        self.verticalLayout_12.setSpacing(0)
        self.verticalLayout_12.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_12.setObjectName("verticalLayout_12")
        self.Hash_R = QtWidgets.QTextBrowser(self.groupBox_16)
        self.Hash_R.setObjectName("Hash_R")
        self.verticalLayout_12.addWidget(self.Hash_R)
        self.verticalLayout_15.addWidget(self.groupBox_16)
        self.groupBox_18 = QtWidgets.QGroupBox(self.B_box)
        self.groupBox_18.setObjectName("groupBox_18")
        self.verticalLayout_11 = QtWidgets.QVBoxLayout(self.groupBox_18)
        self.verticalLayout_11.setSpacing(6)
        self.verticalLayout_11.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_11.setObjectName("verticalLayout_11")
        self.frame_9 = QtWidgets.QFrame(self.groupBox_18)
        self.frame_9.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_9.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_9.setObjectName("frame_9")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.frame_9)
        self.horizontalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.RSA_B_Pri_Label = QtWidgets.QLabel(self.frame_9)
        self.RSA_B_Pri_Label.setObjectName("RSA_B_Pri_Label")
        self.horizontalLayout_5.addWidget(self.RSA_B_Pri_Label)
        self.RSA_B_Pri_Editor = QtWidgets.QLineEdit(self.frame_9)
        self.RSA_B_Pri_Editor.setMinimumSize(QtCore.QSize(70, 0))
        self.RSA_B_Pri_Editor.setObjectName("RSA_B_Pri_Editor")
        self.horizontalLayout_5.addWidget(self.RSA_B_Pri_Editor)
        self.RSA_B_Pri_Sel_Button = QtWidgets.QToolButton(self.frame_9)
        self.RSA_B_Pri_Sel_Button.setObjectName("RSA_B_Pri_Sel_Button")
        self.horizontalLayout_5.addWidget(self.RSA_B_Pri_Sel_Button)
        self.verticalLayout_11.addWidget(self.frame_9)
        self.frame_10 = QtWidgets.QFrame(self.groupBox_18)
        self.frame_10.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_10.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_10.setObjectName("frame_10")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout(self.frame_10)
        self.horizontalLayout_6.setSpacing(6)
        self.horizontalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.RSA_A_Pub_Label = QtWidgets.QLabel(self.frame_10)
        self.RSA_A_Pub_Label.setObjectName("RSA_A_Pub_Label")
        self.horizontalLayout_6.addWidget(self.RSA_A_Pub_Label)
        self.RSA_A_Pub_Editor = QtWidgets.QLineEdit(self.frame_10)
        self.RSA_A_Pub_Editor.setMinimumSize(QtCore.QSize(70, 0))
        self.RSA_A_Pub_Editor.setObjectName("RSA_A_Pub_Editor")
        self.horizontalLayout_6.addWidget(self.RSA_A_Pub_Editor)
        self.RSA_A_PUB_Sel_Button = QtWidgets.QToolButton(self.frame_10)
        self.RSA_A_PUB_Sel_Button.setObjectName("RSA_A_PUB_Sel_Button")
        self.horizontalLayout_6.addWidget(self.RSA_A_PUB_Sel_Button)
        self.verticalLayout_11.addWidget(self.frame_10)
        self.verticalLayout_15.addWidget(self.groupBox_18)
        self.verticalLayout_15.setStretch(0, 2)
        self.verticalLayout_15.setStretch(1, 1)
        self.verticalLayout_15.setStretch(2, 1)
        self.verticalLayout_15.setStretch(3, 2)
        self.horizontalLayout_7.addWidget(self.B_box)
        self.horizontalLayout_7.setStretch(0, 4)
        self.horizontalLayout_7.setStretch(2, 2)
        self.verticalLayout_16.addWidget(self.frame_11)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 989, 21))
        self.menubar.setObjectName("menubar")
        self.menutools = QtWidgets.QMenu(self.menubar)
        self.menutools.setObjectName("menutools")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.action_generate_des_key = QtWidgets.QAction(MainWindow)
        self.action_generate_des_key.setObjectName("action_generate_des_key")
        self.action_generate_aes_key = QtWidgets.QAction(MainWindow)
        self.action_generate_aes_key.setObjectName("action_generate_aes_key")
        self.action_generate_rsa_key = QtWidgets.QAction(MainWindow)
        self.action_generate_rsa_key.setObjectName("action_generate_rsa_key")
        self.menutools.addAction(self.action_generate_des_key)
        self.menutools.addAction(self.action_generate_aes_key)
        self.menutools.addAction(self.action_generate_rsa_key)
        self.menubar.addAction(self.menutools.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QtWidgets.QApplication.translate("MainWindow", "MainWindow", None, -1))
        self.A_box.setTitle(QtWidgets.QApplication.translate("MainWindow", "用户A", None, -1))
        self.groupBox.setTitle(QtWidgets.QApplication.translate("MainWindow", "明文", None, -1))
        self.Hash_function_selection.setTitle(QtWidgets.QApplication.translate("MainWindow", "哈希函数", None, -1))
        self.MD5.setText(QtWidgets.QApplication.translate("MainWindow", "MD5", None, -1))
        self.SHA.setText(QtWidgets.QApplication.translate("MainWindow", "SHA", None, -1))
        self.sym_encryption_selection.setTitle(QtWidgets.QApplication.translate("MainWindow", "对称加密算法", None, -1))
        self.DES.setText(QtWidgets.QApplication.translate("MainWindow", "DES", None, -1))
        self.AES.setText(QtWidgets.QApplication.translate("MainWindow", "AES", None, -1))
        self.key_selection.setTitle(QtWidgets.QApplication.translate("MainWindow", "公/密钥选择", None, -1))
        self.RSA_A_Pri_Label.setText(QtWidgets.QApplication.translate("MainWindow", "A的RSA私钥 :", None, -1))
        self.RSA_A_Pri_Sel_Button.setText(QtWidgets.QApplication.translate("MainWindow", "...", None, -1))
        self.RSA_B_Pub_Label.setText(QtWidgets.QApplication.translate("MainWindow", "B的RSA公钥 :", None, -1))
        self.RSA_B_Pub_Sel_Button.setText(QtWidgets.QApplication.translate("MainWindow", "...", None, -1))
        self.DES_AES_Label.setText(QtWidgets.QApplication.translate("MainWindow", "DES密钥    :", None, -1))
        self.AES_DES_Key_Sel_Button.setText(QtWidgets.QApplication.translate("MainWindow", "...", None, -1))
        self.groupBox_8.setTitle(QtWidgets.QApplication.translate("MainWindow", "工具", None, -1))
        self.Button_Generate_DES_Key.setText(QtWidgets.QApplication.translate("MainWindow", "DES密钥生成", None, -1))
        self.Button_Generate_Aes_key.setText(QtWidgets.QApplication.translate("MainWindow", "AES密钥生成", None, -1))
        self.Button_Generate_RSA_Key.setText(QtWidgets.QApplication.translate("MainWindow", "RSA密钥生成", None, -1))
        self.A_SendMsg_button.setText(QtWidgets.QApplication.translate("MainWindow", "发送", None, -1))
        self.B_box.setTitle(QtWidgets.QApplication.translate("MainWindow", "用户B", None, -1))
        self.groupBox_15.setTitle(QtWidgets.QApplication.translate("MainWindow", "解密后的明文", None, -1))
        self.groupBox_17.setTitle(QtWidgets.QApplication.translate("MainWindow", "计算得到的HASH值", None, -1))
        self.groupBox_16.setTitle(QtWidgets.QApplication.translate("MainWindow", "HASH值校验结果", None, -1))
        self.groupBox_18.setTitle(QtWidgets.QApplication.translate("MainWindow", "公/密钥选择", None, -1))
        self.RSA_B_Pri_Label.setText(QtWidgets.QApplication.translate("MainWindow", "B的RSA私钥 :", None, -1))
        self.RSA_B_Pri_Sel_Button.setText(QtWidgets.QApplication.translate("MainWindow", "...", None, -1))
        self.RSA_A_Pub_Label.setText(QtWidgets.QApplication.translate("MainWindow", "A的RSA公钥 :", None, -1))
        self.RSA_A_PUB_Sel_Button.setText(QtWidgets.QApplication.translate("MainWindow", "...", None, -1))
        self.menutools.setTitle(QtWidgets.QApplication.translate("MainWindow", "工具", None, -1))
        self.action_generate_des_key.setText(QtWidgets.QApplication.translate("MainWindow", "DES密钥生成", None, -1))
        self.action_generate_aes_key.setText(QtWidgets.QApplication.translate("MainWindow", "AES密钥生成", None, -1))
        self.action_generate_rsa_key.setText(QtWidgets.QApplication.translate("MainWindow", "RSA公/私钥生成", None, -1))
