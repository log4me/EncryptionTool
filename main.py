# This Python file uses the following encoding: utf-8
import config as cfg
import sys
from PySide2.QtWidgets import QApplication, QMainWindow
from event.mainwindow import MainWindow


def main():
    app = QApplication([])
    mainwindow = MainWindow()
    mainwindow.show()
    err_code = app.exec_()
    sys.exit(err_code)


if __name__ == "__main__":
    main()
