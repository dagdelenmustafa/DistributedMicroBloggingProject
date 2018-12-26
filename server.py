#!/usr/bin/python3
import random
import socket
import signal
import sys
from functools import partial
import queue
import threading
from datetime import datetime, time
import time

import yaml
import requests
import uuid
import hashlib


from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import QThread
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton
from PyQt5.uic import loadUi

from Cryptodome.PublicKey import RSA
from Cryptodome import Random


# TODO: Arayüz Ayrıntıları yapılacak
# TODO: Belirli aralıklarla Arayüzün yenilenmesi sağlanacak
# TODO: Public Private Key ikilisi eklenmesi yapılacak
# TODO: RefreshThread tüm alanlar için yapılacak
# TODO: Yayınlama protokolü yapılacak

#CONDITIONS
from mainwindow3_ui import Ui_MainWindow

new_user = "0"
new_subscribe_request = "1"



def create_rsa_pair():
    random_generator = Random.new().read

    # new key pair generation
    new_key = RSA.generate(2048, randfunc=random_generator)

    # get the public key and show it
    public_key = new_key.publickey()
    publicKey=public_key.exportKey("PEM")


    # get the private key and print
    # private key is given directly with the pair handle
    private_key = new_key

    privateKey=new_key.exportKey("PEM")


    # write to files
    f = open('app_data/rsa_private.txt','w')
    f.write(private_key.exportKey().decode())
    f.close()

    f = open('app_data/rsa_public.txt','w')
    f.write(public_key.exportKey().decode())
    f.close()
    
    return publicKey,privateKey


def signal_handler(connections, signal, frame):
    global terminate_all_thread
    # Closing LoggerThread
    terminate_all_thread = True
    print("Bitiş " + str(threading.enumerate()))
    for k, v in connections.items():
        v[0].put("Server Closed\n")
        v[1].close()
    sys.exit(0)



class LoggerThread(threading.Thread):

    def __init__(self, logger_queue):
        threading.Thread.__init__(self)
        self.logger_queue = logger_queue

    def run(self):
        global terminate_all_thread
        openfile = "app_data/Server_Logs.txt"
        f = open(openfile, 'w')
        while not terminate_all_thread:
            if not self.logger_queue.empty():
                print(self.logger_queue.get(), file=f, flush=True)



class New_Peer_Thread(threading.Thread):

    def __init__(self, peer_list, my_ip, my_port, my_username, my_type, my_hash):
        threading.Thread.__init__(self)
        self.peer_list = peer_list
        self.my_ip = my_ip
        self.my_port = my_port
        self.my_username = my_username
        self.my_type = my_type
        self.message = "LSQ"
        self.USRString = "USR " + str(my_username) + " " + str(my_ip) + " " + str(my_port) + " " + str(my_hash) + " " + str(my_type)

    def run(self):
        global terminate_all_thread
        while not terminate_all_thread:
            time.sleep(120)
            for k, v in self.peer_list.items():
                s = socket.socket()
                s.connect((v[0], int(v[1])))
                s.send(self.USRString.encode)
                s.send(self.message.encode())
                s.close()


class ReaderThread(threading.Thread):
    def __init__(self, connection, addr, name, connections, loggerQueue,
                 messageQueue, peerList, terminateThread, my_subscribers,
                 black_list, my_subscribe_request, sended_subscribe_request,
                 subscribed_peers, peer_list_that_block_me):
        threading.Thread.__init__(self)
        self.connection = connection
        self.addr = addr
        self.name = name
        self.connections = connections
        self.loggerQueue = loggerQueue
        self.messageQueue = messageQueue
        self.peerList = peerList
        self.terminateThread = terminateThread
        self.my_subscribers = my_subscribers
        self.black_list = black_list
        self.my_subscribe_request = my_subscribe_request
        self.sended_subscribe_request = sended_subscribe_request
        self.subscribed_peers = subscribed_peers
        self.peer_list_that_block_me = peer_list_that_block_me

    def run(self):
        print(self.connection)
        print(self.addr)
        self.loggerQueue.put(str(datetime.now()) + " - Got New Connection from" + str(self.addr))
        self.loggerQueue.put(str(datetime.now()) + " - " + self.name + " Starting")
        self.messageQueue.put("Connected to server\n")
        readAndParse(self.connection, self.connections, self.messageQueue,
                     self.peerList, self.terminateThread, self.my_subscribers, self.black_list,
                     self.my_subscribe_request, self.sended_subscribe_request, self.subscribed_peers,
                     self.peer_list_that_block_me)
        self.loggerQueue.put(str(datetime.now()) + " - " + self.name + " Exiting")


def readAndParse(connection, connections, message_queue, peer_list, terminateThread,
                 my_subscribers, black_list, my_subscribe_request, sended_subscribe_request,
                 subscribed_peers, peer_list_that_block_me):
    global terminate_all_thread, widget
    peer_username = "NULL"
    err_count = 0
    while not terminate_all_thread and not terminateThread:
        try:
            receivedObjects = connection.recv(1024).decode()
        except:
            print("Connection Close " + str(connection))
            break
        receivedObject = receivedObjects.split(" ", 1)
        receivedObject[0] = receivedObject[0].replace("\n", "")
        receivedObject[0] = receivedObject[0].replace("\r", "")

        print(receivedObject)
        print(receivedObject.__len__())
        if receivedObject.__len__() == 2:
            receivedObject[1] = receivedObject[1].strip()
            receivedObject[1] = receivedObject[1].replace("\n", "")
            receivedObject[1] = receivedObject[1].replace("\r", "")

        if receivedObjects == "":
            err_count = err_count + 1
            if err_count == 20:
                if peer_username != "NULL":
                    connections.pop(peer_username)
                print("Ending with counter " + str(threading.enumerate()))
                message_queue.put("BYE")
                terminateThread = True


        if receivedObject[0] == "USR" and receivedObject.__len__() != 6:
            if receivedObject[1] != "":
                received_object_for_new_user = receivedObject[1].split(" ")
                username_check = peer_list.get(received_object_for_new_user[0], "NULL")
                if username_check == "NULL":
                    if received_object_for_new_user.__len__() == 5:
                        print("New User Register")
                        peer_username = received_object_for_new_user[0]
                        peer_ip = received_object_for_new_user[1]
                        peer_port = received_object_for_new_user[2]
                        peer_hash = received_object_for_new_user[3]
                        peer_type = received_object_for_new_user[4]
                        # TODO: boşluk karakteri ile test et
                        connections[peer_username] = [message_queue, connection]
                        peer_list[peer_username] = [peer_ip, peer_port, peer_hash, peer_type, str(time.ctime()), "ON"]
                        message_queue.put("HEL " + peer_username + "\n")
                        refresh_ui_queue.put(new_user + ":" + peer_username)
                    else:
                        message_queue.put("ERR\n")
                else:
                    if received_object_for_new_user[0] in black_list:
                        message_queue.put("BLC\n")
                    else:
                        print("User Login")
                        peer_username = received_object_for_new_user[0]
                        connections[peer_username] = [message_queue, connection]
                        #Signature ile kontrol yapılabilir.
            else:
                message_queue.put("ERR\n")


        elif receivedObject[0] == "LSQ" and receivedObject.__len__() == 1:
            if peer_username in black_list:
                message_queue.put("BLC\n")
            else:
                if peer_username != "NULL":
                    message_queue.put("LSA " + str(peer_list) + "\n")
                else:
                    message_queue.put("ERL\n")

        elif receivedObject[0] == "LSA":
            if peer_username != "NULL" and receivedObject.__len__() != 1:
                received_peer_list = yaml.load(receivedObject[1])
                for k,v in received_peer_list.items():
                    if k in peer_list.keys():
                        continue
                    else:
                        print("New User From LSA")
                        peer_list[k] = v

            else:
                message_queue.put("ERL\n")



        elif receivedObject[0] == "TIC" and receivedObject.__len__() == 1:
            message_queue.put("TOC\n")


        elif receivedObject[0] == "MSG" and receivedObject.__len__() > 1:
            if peer_username in black_list:
                message_queue.put("BLC\n")
            else:
                if peer_username != "NULL":
                    if receivedObject[1] != "":
                        # TODO: MSG mustafa yazması durumunda hata alınıyor delimite içermiyorsa ERR gönder
                        delimiter = ":"
                        targetUserAndMessage = receivedObject[1]
                        splitedTargetUserAndMessage = targetUserAndMessage.split(delimiter, 1)
                        targetUser = splitedTargetUserAndMessage[0]
                        finalMessage = splitedTargetUserAndMessage[1]
                        targetMessageQueue = connections.get(targetUser, "NULL")
                        if targetMessageQueue != "NULL":
                            connections[targetUser][0].put("MSG " + peer_username + ":" + finalMessage + "\n")
                            message_queue.put("MOK\n")
                        else:
                            message_queue.put("MNO\n")
                    else:
                        message_queue.put("ERR\n")
                else:
                    message_queue.put("ERL\n")



        elif receivedObject[0] == "SBS" and receivedObject.__len__() == 1:
            if peer_username in black_list:
                message_queue.put("BLC\n")
            else:
                if peer_username != "NULL":
                    print(peer_username)
                    my_subscribe_request.append(peer_username)
                    refresh_ui_queue.put(new_subscribe_request)
                else:
                    message_queue.put("ERL\n")



        elif receivedObject[0] == "SBO" and receivedObject.__len__() == 1:
            if peer_username in black_list:
                message_queue.put("BLC\n")
            else:
                if peer_username != "NULL":
                    index = sended_subscribe_request.index(peer_username)
                    del sended_subscribe_request[index]
                    subscribed_peers.append(peer_username)
                else:
                    message_queue.put("ERL\n")



        elif receivedObject[0] == "SNO" and receivedObject.__len__() == 1:
            if peer_username in black_list:
                message_queue.put("BLC\n")
            else:
                if peer_username != "NULL":
                    index = sended_subscribe_request.index(peer_username)
                    del sended_subscribe_request[index]
                else:
                    message_queue.put("ERL\n")



        elif receivedObject[0] == "BLU" and receivedObject.__len__() == 1:
            if peer_username != "NULL":
                peer_list_that_block_me.append(peer_username)
                message_queue.put("BLO\n")
            else:
                message_queue.put("ERL\n")



        elif receivedObject[0] == "UBL" and receivedObject.__len__() == 1:
            if peer_username != "NULL":
                index = peer_list_that_block_me.index(peer_username)
                del peer_list_that_block_me[index]
                message_queue.put("UBO\n")
            else:
                message_queue.put("ERL\n")



        elif receivedObject[0] == "QUI" and receivedObject.__len__() == 1:
            if peer_username != "NULL":
                message_queue.put("BYE " + peer_username + "\n")
                for k, v in connections.items():
                    v[0].put("SYS " + peer_username + " has left.\n")
                connections.pop(peer_username)
            else:
                message_queue.put("BYE\n")
            print("Ending with QUI" + str(threading.enumerate()))
            terminateThread = True

        elif receivedObject[0] == "SOK" or receivedObject[0] == "MOK" or receivedObject[0] == "YOK"\
                or receivedObject[0] == "TOK" or receivedObject[0] == "PSO":
            print(receivedObject[0])
            pass


        else:
            message_queue.put("ERR\n")

'''
        elif receivedObject[0] == "SAY":
            if peer_username != "NULL":
                if not receivedObject[1].isspace():
                    message = receivedObject[1]
                    for k, v in connections.items():
                        v[0].put("SAY " + peer_username + ":" + message + "\n")
                    messageQueue.put("SOK\n")
                else:
                    messageQueue.put("ERR\n")
            else:
                messageQueue.put("ERL\n")
'''


class WriterThread(threading.Thread):
    def __init__(self, connection, addr, name, connections, loggerQueue, messageQueue, peer_list, terminateThread):
        threading.Thread.__init__(self)
        self.connection = connection
        self.addr = addr
        self.name = name
        self.connections = connections
        self.loggerQueue = loggerQueue
        self.messageQueue = messageQueue
        self.peer_list = peer_list
        self.terminateThread = terminateThread

    def run(self):
        self.loggerQueue.put(str(datetime.now()) + " - " + self.name + " Starting")
        writeMessage(self.connection, self.messageQueue, self.terminateThread)
        self.loggerQueue.put(str(datetime.now()) + " - " + self.name + " Exiting")


def writeMessage(connection, message_queue, terminateThread):
    while not terminateThread:
        if not message_queue.empty() and not terminateThread:
            message = message_queue.get()
            connection.send(message.encode())
            if message.startswith("BYE"):
                break

    connection.close()



#TODO: Bu thread Qt Arayüz threadi olacak
class QtSideAndClient(QtWidgets.QMainWindow):
    def __init__(self, connections, logger_queue, peer_list, my_ip, my_port,
                 my_username, my_type, my_subscribers, my_subscribe_request,
                 subscribed_peers, black_list,
                 sended_subscribe_request, peer_list_that_block_me, my_hash):
        super(QtSideAndClient, self).__init__()
        self.connections = connections
        self.logger_queue = logger_queue
        self.peer_list = peer_list
        self.my_ip = my_ip
        self.my_port = my_port
        self.my_username = my_username
        self.my_type = my_type
        self.my_subscribers = my_subscribers
        self.my_subscribe_request = my_subscribe_request
        self.subscribed_peers = subscribed_peers
        self.black_list =black_list
        self.sended_subscribe_request = sended_subscribe_request
        self.peer_list_that_block_me = peer_list_that_block_me
        self.my_hash = my_hash
        self.USRString = "USR " + str(my_username) + " " + str(my_ip) + " " + str(my_port) + " " + str(my_hash) + " " + str(my_type)
        self.refreshUI()


    def refreshUI(self):
        self.qt_app = QtWidgets.QApplication(['Hello'])
        # print(type(sys.argv))
        QtWidgets.QWidget.__init__(self, None)

        # create the main ui
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.btn_publish_blog.pressed.connect(self.publish_blog)
        self.ui.btn_get_my_blog.pressed.connect(self.get_my_blogs)
        self.model = QStandardItemModel(self.ui.lw_peer_list)

        self.ui.lw_peer_list.clicked.connect(self.peer_list_on_click)

        self.refresh_thread = RefreshThread()
        self.refresh_thread.ready_refresh.connect(self.on_UI_ready)
        self.refresh_thread.start()



    def on_UI_ready(self, data):
        data = data.split(":", 1)

        if data[0] == new_user:
            item = QStandardItem()
            item.setText(data[1])
            item.setEditable(False)
            item.setData(data[1])
            self.model.appendRow(item)

            self.ui.lw_peer_list.setModel(self.model)
            self.ui.lw_peer_list.show()

    def publish_blog(self):
        blog_text = self.ui.et_publish_blog.toPlainText()
        self.ui.et_publish_blog.setPlainText("")
        openfile = "app_data/" + self.my_username + ".txt"
        f = open(openfile, 'a+')
        f.write(blog_text + "\n")
        f.close()
        m = hashlib.md5()
        m.update((blog_text + " " + str(datetime.now())).encode())
        self.my_hash = m.hexdigest()
        for i in range(self.my_subscribers.__len__()):
            peer = self.peer_list.get(self.my_subscribers[i], "NULL")
            if peer != "NULL":
                s = socket.socket()
                print(peer[0])
                print(peer[1])
                s.connect((peer[0], int(peer[1])))
                s.send(self.USRString.encode)
                message = "PSH " + blog_text
                s.send(message.encode())
                s.close()
            else:
                print("NULL VAR")

    def get_my_blogs(self):
        fid = open("app_data/" + self.my_username + ".txt", 'r')
        model = QStandardItemModel(self.ui.lw_blogs)

        for line in fid:
            item = QStandardItem()
            item.setText(line)
            item.setEditable(False)
            model.appendRow(item)
        fid.close()
        self.ui.lw_blogs.setModel(model)
        self.ui.lw_blogs.show()

    def peer_list_on_click(self):
        self.clicked_user_name = self.ui.lw_peer_list.selectedIndexes()[0].data()
        if self.clicked_user_name in self.sended_subscribe_request:
            self.ui.btn_subscribe_user.setText("Beklemede")
        elif self.clicked_user_name in self.subscribed_peers:
            self.ui.btn_subscribe_user.setText("Takip Ediliyor")
        elif self.clicked_user_name in self.peer_list_that_block_me:
            self.ui.btn_subscribe_user.setText("Engellendin")
        elif self.clicked_user_name in self.black_list:
            self.ui.btn_subscribe_user.setText("Engellendi")
        else:
            self.ui.btn_subscribe_user.setEnabled(True)
            self.ui.btn_subscribe_user.pressed.connect(self.subscribe_user)
            self.ui.btn_subscribe_user.setText("Abone Ol")

        if self.clicked_user_name in self.black_list:
            self.ui.btn_block_user.setText("Engellendi")
        else:
            self.ui.btn_block_user.setText("Engelle")

        self.ui.btn_block_user.setEnabled(True)
        self.ui.btn_block_user.pressed.connect(self.block_user)

    def subscribe_user(self):
        peer = self.peer_list.get(self.clicked_user_name, "NULL")
        if peer != "NULL":
            self.ui.btn_subscribe_user.setText("Beklemede")
            s = socket.socket()
            print(peer[0])
            print(peer[1])
            s.connect((peer[0], int(peer[1])))
            s.send(self.USRString.encode)
            message = "SBS"
            s.send(message.encode())
            s.close()
            self.sended_subscribe_request.append(self.clicked_user_name)

        else:
            print("NULL VAR")


    def block_user(self):
        peer = self.peer_list.get(self.clicked_user_name, "NULL")
        if peer != "NULL":
            s = socket.socket()
            print(peer[0])
            print(peer[1])
            s.connect((peer[0], int(peer[1])))
            s.send(self.USRString.encode)
            message = "BLU"
            s.send(message.encode())
            s.close()
            self.black_list.append(self.clicked_user_name)
            self.ui.btn_block_user.setText("Engellendi")
        else:
            print("NULL VAR")

    def run(self):
        self.show()
        self.qt_app.exec_()

'''
        global widget
        loadUi('Denemeler/mainwindow3.ui', self)
        self.setWindowTitle('Deneme')
        # Container Widget


        widget = QWidget()
        # Layout of Container Widget
        layout = QVBoxLayout(self)
        for k, v in self.peer_list.items():
            btn = QPushButton(k)
            btn.setObjectName(k)
            btn.clicked.connect(partial(self.button_pressed, k))
            layout.addWidget(btn)
        widget.setLayout(layout)
        self.scrollArea_all_peers.setWidget(widget)


        widget1 = QWidget()
        layout1 = QVBoxLayout(self)
        # Layout of Container Widget
        for i in range(self.my_subscribe_request.__len__()):
            btn = QPushButton(self.my_subscribe_request[i])
            btn.setObjectName(self.my_subscribe_request[i])
            btn.clicked.connect(partial(self.button_pressed, self.my_subscribe_request[i]))
            layout1.addWidget(btn)
        widget1.setLayout(layout1)
        self.scrollArea_subscriber_requests.setWidget(widget1)



        #self.textBrowser.setText("deneme")
        self.pushButton.pressed.connect(self.publish_blog)
        self.refresh_thread = RefreshThread()
        self.refresh_thread.ready_refresh.connect(partial(self.on_UI_ready, widget, widget1, layout, layout1))
        self.refresh_thread.start()
        self.show()


    def button_pressed(self, k):
        print('Button pressed' + str(k))

    def on_UI_ready(self, widget, widget1, layout, layout1,data):
        items = (layout.itemAt(i).widget().objectName() for i in range(layout.count()))
        items = list(items)

        if data == new_user:
            for k, v in self.peer_list.items():
                if k not in items:
                    btn = QPushButton(k)
                    btn.setObjectName(k)
                    btn.clicked.connect(partial(self.button_pressed, k))
                    layout.addWidget(btn)
                    widget.setLayout(layout)
        else:
            for i in range(self.my_subscribe_request.__len__()):
                peer = self.peer_list.get(self.my_subscribe_request[i])
                btn = QPushButton(str(self.my_subscribe_request[i]))
                btn.setObjectName(str(self.my_subscribe_request[i]))
                btn.clicked.connect(partial(self.button_pressed, str(self.my_subscribe_request[i])))
                layout1.addWidget(btn)
                widget1.setLayout(layout1)

    def publish_blog(self):
        blog_text = self.textEdit.toPlainText()
        openfile = "app_data/"+self.my_username+".txt"
        f = open(openfile, 'a+')
        f.write(blog_text + "\n")
        m = hashlib.md5()
        m.update((blog_text + " " + str(datetime.now())).encode())
        self.my_hash = m.hexdigest()
        for i in range(self.my_subscribers.__len__()):
            peer = self.peer_list.get(self.my_subscribers[i], "NULL")
            if peer != "NULL":
                s = socket.socket()
                print(peer[0])
                print(peer[1])
                s.connect((peer[0], int(peer[1])))
                s.send(self.USRString.encode)
                message = "PSH " + blog_text
                s.send(message.encode())
                s.close()
            else:
                print("NULL VAR")
    '''


class RefreshThread(QThread):
    ready_refresh = QtCore.pyqtSignal(object)
    def __init__(self):
        QThread.__init__(self)
        self.i = 1
    # run method gets called when we start the thread
    def run(self):
        while True:
            if not refresh_ui_queue.empty():
                condition = refresh_ui_queue.get()
                self.ready_refresh.emit(condition)

'''
class ClientThread(threading.Thread):

    def __init__(self, connection_type, destination, my_ip, my_port, my_type, my_username, message):
        threading.Thread.__init__(self)
        self.connection_type = connection_type
        self.destination = destination
        self.my_ip = my_ip
        self.my_port = my_port
        self.my_type = my_type
        self.my_username = my_username
        self.message = message

    def run(self):
        USRString = "USR " + self.my_username + " " + self.my_ip + " " + self.my_port + " " + self.my_type
        if self.connection_type == 0:
            s = socket.socket()
            s.connect((self.destination[0], self.destination[1]))
            s.send(USRString.encode())
            s.send(self.message)

        elif self.connection_type == 1:
            # TODO: Tüm sisteme gönderilecek Protokol mesajları için örneğin LSQ yada sadece subscriberlara göndermek için
            for k, v in self.destination.items():
                s = socket.socket()
                s.connect(v[0], v[1])
                s.send(USRString.encode())
                s.send(self.message)
                # TODO: USR ile kendini tanıt sonra mesajı gönder

'''


class ServerThread(threading.Thread):

    def __init__(self, s, connections, logger_queue, peer_list, my_subscribers, black_list,
                 my_subscribe_request, sended_subscribe_request, subscribed_peers,
                 peer_list_that_block_me):
        threading.Thread.__init__(self)
        self.s = s
        self.connections = connections
        self.logger_queue = logger_queue
        self.peer_list = peer_list
        self.my_subscribers = my_subscribers
        self.black_list = black_list
        self.my_subscribe_request = my_subscribe_request
        self.sended_subscribe_request = sended_subscribe_request
        self.subscribed_peers = subscribed_peers
        self.peer_list_that_block_me = peer_list_that_block_me
        self.connection_id = 0

    def run(self):
        print("server thread running")
        while True:
            connection, addr = self.s.accept()
            message_queue = queue.Queue()
            terminateThread = False
            server_reader_thread = ReaderThread(connection, addr, str(self.connection_id) + '.ReaderThread', self.connections,
                                                self.logger_queue, message_queue, self.peer_list, terminateThread, self.my_subscribers,
                                                self.black_list, self.my_subscribe_request, self.sended_subscribe_request, self.subscribed_peers,
                                                self.peer_list_that_block_me)
            server_reader_thread.start()
            server_writer_thread = WriterThread(connection, addr, str(self.connection_id) + '.WriterThread', self.connections, self.logger_queue, message_queue, self.peer_list, terminateThread)
            server_writer_thread.start()
            self.connection_id = self.connection_id + 1
            print(threading.enumerate())



def main():
    global terminate_all_thread, refresh_ui_queue
    terminate_all_thread = False


    connections = {}
    peer_list = {}
    my_subscribers = []
    my_subscribe_request = []
    sended_subscribe_request = []
    subscribed_peers = []
    black_list = []
    peer_list_that_block_me = []
    logger_queue = queue.Queue()
    refresh_ui_queue = queue.Queue()
    signal.signal(signal.SIGINT, partial(signal_handler, connections))

    s = socket.socket()
    host = "0.0.0.0"
    port = 12344
    s.bind((host, port))
    s.listen()

    logger_thread = LoggerThread(logger_queue).start()

    #my_ip = requests.get('http://ip.42.pl/raw').text
    my_ip = socket.gethostbyname(socket.gethostname())
    print(my_ip)
    my_port = 12344
    my_username = str(uuid.NAMESPACE_DNS.hex)
    my_type = "Y"
    m = hashlib.md5()
    m.update((my_username +  " " + str(datetime.now())).encode())
    my_hash = m.hexdigest()

    new_peer_thread = New_Peer_Thread(peer_list, my_ip, my_port, my_username, my_type, my_hash)
    new_peer_thread.start()



    server_thread = ServerThread(s, connections, logger_queue, peer_list, my_subscribers, black_list,
                                 my_subscribe_request, sended_subscribe_request, subscribed_peers,
                                 peer_list_that_block_me)
    server_thread.start()


    my_subscribers.append("mustafa")
    app = QtWidgets.QApplication(sys.argv)
    qt_and_client = QtSideAndClient(connections, logger_queue, peer_list, my_ip, my_port,
                                    my_username, my_type, my_subscribers, my_subscribe_request,
                                    subscribed_peers, black_list,
                                    sended_subscribe_request, peer_list_that_block_me, my_hash)
    qt_and_client.run()
    app.exec_()


if __name__ == "__main__":
    main()
