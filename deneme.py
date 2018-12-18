'''import math
import random
import yaml

print(math.log(40,4))

deneme = {}

deneme["mustafa"] = 1
deneme["dagdelen"] = 2

id, number = random.choice(list(deneme.items()))
print(id, number)


deneme = "1 2 3 4 5"
denem = deneme.split(" ", 1)
denem[1] = denem[1].split(" ")
print(denem)


deneme = "LSQ"
dene = deneme.split(" ", 1)
print(dene)

deneme2 = {}
deneme2["mustaf1a"] = "deneme123"
deneme1 = {}
deneme1["mustafa"] = ["deneme", "deneme2", "deneme3", "deneme4"]
deneme1["mustafa1"] = ["deneme", "deneme2", "deneme3", "deneme4"]
splited = str(deneme1)
print(splited)
print(deneme2)
d = yaml.load(splited)
for k,v in d.items():
    if k in deneme2.keys():
        print("VAR")
    else:
        print("Yok")
        deneme2[k] = v
print(deneme2)
received = [[0,1,2,3,4,5], 1,3,4,5]
print(received[0].__len__())
username_check = deneme2.get("mustafa", "NULL")
black_list = []
black_list.append("mustafasad")
if "mustafa" in black_list:
    print("VAR")
else:
    print("YOK")
print(username_check)
import requests
print(requests.get('http://ip.42.pl/raw').text)

import sys

from PyQt5.QtCore import  pyqtSlot
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton
from PyQt5.uic import loadUi


class mainwindow(QMainWindow):
    def __init__(self, parent = None):
        super(mainwindow, self).__init__()
        loadUi('mainwindow.ui', self)
        self.setWindowTitle('Deneme')
        #Container Widget
        widget = QWidget()
        #Layout of Container Widget
        layout = QVBoxLayout(self)
        for _ in range(100):
            btn = QPushButton()
            layout.addWidget(btn)
        widget.setLayout(layout)
        self.scrollArea_all_peers.setWidget(widget)
        self.textBrowser.setText("deneme")


app = QApplication(sys.argv)
widget = mainwindow()
widget.show()
sys.exit(app.exec_())

'''
