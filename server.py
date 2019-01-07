#!/usr/bin/python3
import os
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
import uuid
import hashlib

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import QThread
from PyQt5.QtGui import QStandardItem, QStandardItemModel, QColor
from uuid import getnode as get_mac
from Cryptodome.PublicKey import RSA
from Cryptodome import Random

# TODO: Arayüz Ayrıntıları yapılacak
# TODO: Belirli aralıklarla Arayüzün yenilenmesi sağlanacak
# TODO: Public Private Key ikilisi eklenmesi yapılacak
# TODO: RefreshThread tüm alanlar için yapılacak
# TODO: Yayınlama protokolü yapılacak

# CONDITIONS
from mainwindow3_ui import Ui_MainWindow

new_user = "0"
new_subscribe_request = "1"
new_message = "2"
new_subscribe = "3"
new_subscribed_peer = "4"
offline_peer = "5"
online_peer = "6"
login = "10"

# PC'nin MAC adresini getir.
mac = get_mac()
# UUID üret
uuid.uuid4()

index_selectedLine = 0


def signal_handler(peer_list, signal, frame):
    global terminate_all_thread
    # Closing LoggerThread
    terminate_all_thread = True
    print("Bitiş " + str(threading.enumerate()))

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
        self.USRString = "USR " + str(my_username) + " " + str(my_ip) + " " + str(my_port) + " " + str(
            my_hash) + " " + str(my_type)

    def run(self):
        global terminate_all_thread
        while not terminate_all_thread:
            time.sleep(10)
            for k, v in self.peer_list.items():
                if not k == self.my_username:
                    try:
                        s = socket.socket()
                        s.connect((v[0], int(v[1])))
                        s.send(self.USRString.encode())
                        time.sleep(1)
                        s.send(self.message.encode())
                        s.close()
                    except:
                        if self.peer_list[k][5] != "OFF":
                            refresh_ui_queue.put(offline_peer + ":" + k)
                            v[5] = "OFF"
                            self.peer_list[k] = v
                            print("OFF")



class ReaderThread(threading.Thread):
    def __init__(self, my_username, connection, addr, name, connections, logger_queue,
                 message_queue, peer_list, terminateThread, my_subscribers,
                 black_list, my_subscribe_request, sended_subscribe_request,
                 subscribed_peers, peer_list_that_block_me, all_messages):
        threading.Thread.__init__(self)
        self.my_username = my_username
        self.connection = connection
        self.addr = addr
        self.name = name
        self.connections = connections
        self.logger_queue = logger_queue
        self.message_queue = message_queue
        self.peer_list = peer_list
        self.terminateThread = terminateThread
        self.my_subscribers = my_subscribers
        self.black_list = black_list
        self.my_subscribe_request = my_subscribe_request
        self.sended_subscribe_request = sended_subscribe_request
        self.subscribed_peers = subscribed_peers
        self.peer_list_that_block_me = peer_list_that_block_me
        self.all_messages = all_messages

    def run(self):
        print(self.connection)
        print(self.addr)
        self.logger_queue.put(str(datetime.now()) + " - Got New Connection from" + str(self.addr))
        self.logger_queue.put(str(datetime.now()) + " - " + self.name + " Starting")
        self.readAndParse()
        self.logger_queue.put(str(datetime.now()) + " - " + self.name + " Exiting")

    def readAndParse(self):
        global terminate_all_thread, widget
        peer_username = "NULL"
        err_count = 0
        while not terminate_all_thread and not self.terminateThread:
            try:
                receivedObjects = self.connection.recv(1024).decode()
                if receivedObjects == "":
                    self.connection.close()
                    break
                    print(receivedObjects)
            except:
                print("self.connection Close " + str(self.connection))
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
                        self.connections.pop(peer_username)
                    print("Ending with counter " + str(threading.enumerate()))
                    self.message_queue.put("BYE")
                    self.terminateThread = True

            if receivedObject[0] == "USR" and receivedObject.__len__() != 6:
                if receivedObject[1] != "":
                    received_object_for_new_user = receivedObject[1].split(" ")
                    username_check = self.peer_list.get(received_object_for_new_user[0], "NULL")
                    if username_check == "NULL":
                        if received_object_for_new_user.__len__() == 5:
                            print("New User Register")
                            self.peer_username = received_object_for_new_user[0]
                            self.peer_ip = received_object_for_new_user[1]
                            self.peer_port = received_object_for_new_user[2]
                            self.peer_hash = received_object_for_new_user[3]
                            self.peer_type = received_object_for_new_user[4]
                            # TODO: boşluk karakteri ile test et
                            self.connections[self.peer_username] = [self.message_queue, self.connection]
                            self.peer_list[self.peer_username] = [self.peer_ip, self.peer_port, self.peer_hash,
                                                                  self.peer_type, str(time.ctime()),
                                                                  "ON"]
                            print(self.peer_list[self.peer_username])
                            self.message_queue.put(
                                "HEL " + self.peer_username + " " + self.peer_ip + " " + self.peer_port + "\n")
                            refresh_ui_queue.put(new_user + ":" + self.peer_username)
                        else:
                            self.message_queue.put("ERR\n")
                    else:
                        if received_object_for_new_user[0] in self.black_list:
                            self.message_queue.put("BLC\n")
                        else:
                            print("User Login")
                            self.peer_username = received_object_for_new_user[0]
                            print(str(self.peer_list[self.peer_username][5]))
                            if self.peer_list[self.peer_username][5] != "ON":
                                refresh_ui_queue.put(online_peer + ":" + self.peer_username)
                                self.peer_list[self.peer_username][5] = "ON"
                                print("ON")
                            # Signature ile kontrol yapılabilir.
                else:
                    self.message_queue.put("ERR\n")


            elif receivedObject[0] == "HEL":
                self.message_queue.put("HEO " + self.peer_username + " " + self.peer_ip + " " + self.peer_port + "\n")
                refresh_ui_queue(login)

            elif receivedObject[0] == "HEO":
                self.peer_list[self.peer_username] = [self.peer_ip, self.peer_port, self.peer_hash, self.peer_type,
                                                      str(time.ctime()), "ON"]

                fid = open("app_data/peer_list.txt", 'a+')
                fid.write(peer_username + ":" + str(self.peer_list[peer_username]) + "\n")
                fid.close()
                refresh_ui_queue.put(new_user + ":" + peer_username)
                print("New User Register")
                print(self.peer_list)

            elif receivedObject[0] == "LSQ" and receivedObject.__len__() == 1:
                if self.peer_username in self.black_list:
                    self.message_queue.put("BLC\n")
                else:
                    if self.peer_username != "NULL":
                        self.message_queue.put("LSA " + self.peer_username + " " + str(self.peer_list) + "\n")
                    else:
                        self.message_queue.put("ERL\n")

            elif receivedObject[0] == "LSA":
                if self.peer_username != "NULL" and receivedObject.__len__() != 1:
                    received_peer_list = yaml.load(receivedObject[1])
                    for k, v in received_peer_list.items():
                        if k in self.peer_list.keys():
                            continue
                        else:
                            print("New User From LSA")
                            self.peer_list[k] = v
                            fid = open("app_data/peer_list.txt", 'a+')
                            fid.write(k + ":" + str(v) + "\n")
                            fid.close()
                            refresh_ui_queue.put(new_user + ":" + k)

                else:
                    self.message_queue.put("ERL\n")



            elif receivedObject[0] == "TIC" and receivedObject.__len__() == 1:
                self.message_queue.put("TOC\n")


            elif receivedObject[0] == "MSG" and receivedObject.__len__() > 1:
                if self.peer_username in self.black_list:
                    self.message_queue.put("BLC " + self.peer_username + "\n")
                else:
                    if self.peer_username != "NULL":
                        message_text = receivedObject[1]
                        self.all_messages.append(message_text)
                        receivedObject_splited = receivedObject[1].split(" ", 3)
                        refresh_ui_queue.put(new_message + ":" + receivedObject_splited[0])
                        fid = open("app_data/messages.txt", 'a+')
                        fid.write(message_text + "\n")
                        fid.close()
                        self.message_queue.put("MOK " + self.peer_username + "\n")
                    else:
                        self.message_queue.put("ERL " + self.peer_username + "\n")



            elif receivedObject[0] == "SBS":
                if self.peer_username in self.black_list:
                    self.message_queue.put("BLC" + self.peer_username + "\n")
                else:
                    if self.peer_username != "NULL":
                        print(self.peer_username)
                        self.my_subscribe_request.append(self.peer_username)
                        refresh_ui_queue.put(new_subscribe_request + ":" + self.peer_username)
                        fid = open("app_data/my_subscribe_request.txt", "a+")
                        fid.write(self.peer_username + "\n")
                        fid.close()
                    else:
                        self.message_queue.put("ERL " + self.peer_username + "\n")


            elif receivedObject[0] == "SBO":
                if self.peer_username in self.black_list:
                    self.message_queue.put("BLC" + self.peer_username + "\n")
                else:
                    if self.peer_username != "NULL":
                        index = self.sended_subscribe_request.index(self.peer_username)
                        del self.sended_subscribe_request[index]
                        self.subscribed_peers.append(peer_username)
                        refresh_ui_queue.put(new_subscribed_peer + ":" + self.peer_username)
                        fid = open("app_data/sended_subscribe_request.txt", "w+")
                        d = fid.readlines()
                        for i in d:
                            if i != self.peer_username:
                                fid.write(i + "\n")
                        fid.close()
                    else:
                        self.message_queue.put("ERL " + self.peer_username + "\n")



            elif receivedObject[0] == "SNO" and receivedObject.__len__() == 1:
                if self.peer_username in self.black_list:
                    self.message_queue.put("BLC " + self.peer_username + "\n")
                else:
                    if self.peer_username != "NULL":
                        index = self.sended_subscribe_request.index(self.peer_username)
                        del self.sended_subscribe_request[index]
                    else:
                        self.message_queue.put("ERL\n")



            elif receivedObject[0] == "BLU" and receivedObject.__len__() == 1:
                if self.peer_username != "NULL":
                    self.peer_list_that_block_me.append(self.peer_username)
                    self.message_queue.put("BLO\n")
                else:
                    self.message_queue.put("ERL" + self.peer_username + "\n")



            elif receivedObject[0] == "UBL" and receivedObject.__len__() == 1:
                if self.peer_username != "NULL":
                    index = self.peer_list_that_block_me.index(self.peer_username)
                    del self.peer_list_that_block_me[index]
                    self.message_queue.put("UBO\n")
                else:
                    self.message_queue.put("ERL\n")



            elif receivedObject[0] == "QUI" and receivedObject.__len__() == 1:
                if self.peer_username != "NULL":
                    self.message_queue.put("BYE " + self.peer_username + "\n")
                    for k, v in self.connections.items():
                        v[0].put("SYS " + self.peer_username + " has left.\n")
                    self.connections.pop(peer_username)
                else:
                    self.message_queue.put("BYE\n")
                print("Ending with QUI" + str(threading.enumerate()))
                self.terminateThread = True

            elif receivedObject[0] == "SOK" or receivedObject[0] == "MOK" or receivedObject[0] == "YOK" \
                    or receivedObject[0] == "TOK" or receivedObject[0] == "PSO":
                print(receivedObject[0])
                pass


            else:
                self.message_queue.put("ERR\n")


'''
        elif receivedObject[0] == "SAY":
            if peer_username != "NULL":
                if not receivedObject[1].isspace():
                    message = receivedObject[1]
                    for k, v in self.connections.items():
                        v[0].put("SAY " + peer_username + ":" + message + "\n")
                    messageQueue.put("SOK\n")
                else:
                    messageQueue.put("ERR\n")
            else:
                messageQueue.put("ERL\n")
'''


class WriterThread(threading.Thread):
    def __init__(self, connection, addr, name, connections, logger_queue, message_queue, peer_list, terminateThread,
                 my_username, my_ip, my_port, my_hash, my_type):
        threading.Thread.__init__(self)
        self.connection = connection
        self.addr = addr
        self.name = name
        self.connections = connections
        self.message_queue = message_queue
        self.logger_queue = logger_queue
        self.peer_list = peer_list
        self.terminateThread = terminateThread
        self.my_username = my_username
        self.my_ip = my_ip
        self.my_port = my_port
        self.my_hash = my_hash
        self.my_type = my_type
        self.USRString = "USR " + str(my_username) + " " + str(my_ip) + " " + str(my_port) + " " + str(
            my_hash) + " " + str(my_type)

    def run(self):
        self.logger_queue.put(str(datetime.now()) + " - " + self.name + " Starting")
        self.writeMessage()
        self.logger_queue.put(str(datetime.now()) + " - " + self.name + " Exiting")

    def writeMessage(self):
        while not self.terminateThread:
            if not self.message_queue.empty() and not self.terminateThread:
                message = self.message_queue.get()
                if message != "":
                    message = message.split(" ", 1)
                    if message[0] == "HEL" or message[0] == "HEO":
                        message_split = message[1].split(" ", 2)  # peer_username peer_ip peer_port
                        s = socket.socket()
                        s.connect((message_split[1], int(message_split[2])))
                        s.send(message[0].encode())
                        s.close()
                    elif message[0] == "LSA":
                        message_split_lsa = message[1].split(" ", 1)
                        peer = self.peer_list.get(message_split_lsa[0].strip(), "NULL")
                        if peer != "NULL":
                            s = socket.socket()
                            s.connect((peer[0], int(peer[1])))
                            s.send(self.USRString.encode())
                            time.sleep(1)
                            s.send((message[0] + " " + message_split_lsa[1]).encode())
                            s.close()
                    else:
                        peer = self.peer_list.get(message[1].strip(), "NULL")
                        if peer != "NULL":
                            s = socket.socket()
                            s.connect((peer[0], int(peer[1])))
                            s.send(self.USRString.encode())
                            time.sleep(1)
                            s.send(message[0].encode())
                            s.close()


# TODO: Bu thread Qt Arayüz threadi olacak
class QtSideAndClient(QtWidgets.QMainWindow):
    def __init__(self, connections, logger_queue, peer_list, my_ip, my_port,
                 my_username, my_type, my_subscribers, my_subscribe_request,
                 subscribed_peers, black_list,
                 sended_subscribe_request, peer_list_that_block_me, my_hash, message_list, my_blogs, all_messages):
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
        self.black_list = black_list
        self.sended_subscribe_request = sended_subscribe_request
        self.peer_list_that_block_me = peer_list_that_block_me
        self.my_hash = my_hash
        self.message_list = message_list
        self.all_messages = all_messages
        self.my_blogs = my_blogs
        self.message_to_selected_index = 0
        self.USRString = "USR " + str(my_username) + " " + str(my_ip) + " " + str(my_port) + " " + str(
            my_hash) + " " + str(my_type)
        self.refreshUI()

    def refreshUI(self):
        self.qt_app = QtWidgets.QApplication(['Hello'])
        # print(type(sys.argv))
        # QtWidgets.QWidget._init_(self, None)

        # create the main ui
        self.ui = Ui_MainWindow()
        self.ui.closeEvent = self.closeEvent
        self.ui.setupUi(self)
        self.clicked_message_user_name = "NULL"

        self.ui.btn_publish_blog.pressed.connect(self.publish_blog)
        self.ui.btn_get_my_blog.pressed.connect(self.get_my_blogs)
        self.ui.btn_reload_messagebox.pressed.connect(self.reload_messagebox)
        self.ui.btn_send_message.pressed.connect(self.send_message)
        self.ui.btn_login.pressed.connect(self.login)
        self.ui.cb_message_to.activated.connect(self.message_to_selected)

        self.ui.lw_peer_list.clicked.connect(self.peer_list_on_click)
        self.ui.lw_inbox.clicked.connect(self.messagebox_on_click)
        self.ui.lw_requests.clicked.connect(self.request_on_click)
        self.load_lasted_blogs()
        self.load_lasted_peers()
        self.load_lasted_messages()
        self.load_subscribers()

        self.refresh_thread = RefreshThread()
        self.refresh_thread.ready_refresh.connect(self.on_UI_ready)
        self.refresh_thread.start()

    def closeEvent(self, event):
        print("Closing")
        open("app_data/peer_list.txt", "w").close()
        for k, v in self.peer_list.items():
            print("içerdeyiz")
            fid = open("app_data/peer_list.txt", "a+")
            fid.write(k + ":" + str(v) + "\n")
            fid.close()

    def login(self):
        self.my_ip = self.ui.et_my_ip.toPlainText()
        self.my_port = self.ui.et_my_port.toPlainText()
        self.peer_ip = self.ui.et_peer_ip.toPlainText()
        self.peer_port = self.ui.et_peer_port.toPlainText()
        self.USRString = "USR " + str(self.my_username) + " " + str(self.my_ip) + " " + str(self.my_port) + " " + str(
            self.my_hash) + " " + str(self.my_type)

        s = socket.socket()
        s.connect((self.peer_ip, int(self.peer_port)))
        s.send(self.USRString.encode())
        time.sleep(1)
        s.close()

    def load_lasted_blogs(self):
        # MyBlogs Loaded
        model = QStandardItemModel(self.ui.lw_blogs)
        self.i = 0
        for line in self.my_blogs:
            item = QStandardItem()
            item.setText(line)
            item.setEditable(False)
            if self.i == 0:
                item.setBackground(QColor("#666666"))
            model.appendRow(item)
            self.i = self.i + 1
        self.ui.lw_blogs.setModel(model)
        self.ui.lw_blogs.show()

    def load_lasted_peers(self):
        # PeerList_Loaded
        model = QStandardItemModel(self.ui.lw_peer_list)
        print(self.peer_list)
        for k, v in self.peer_list.items():
            if not k == self.my_username:
                item = QStandardItem()
                item.setText(k)
                item.setEditable(False)
                model.appendRow(item)
                self.ui.cb_message_to.addItem(k)

        self.ui.lw_peer_list.setModel(model)
        self.ui.lw_peer_list.show()

    def load_lasted_messages(self):
        # Message_list_loaded
        model = QStandardItemModel(self.ui.lw_inbox)
        for line in self.all_messages:
            line = line.split(" ", 3)
            if line[0] == self.my_username and line[1] not in self.message_list:
                self.message_list.append(line[1])
            elif line[0] not in self.message_list and line[0] != self.my_username:
                self.message_list.append(line[0])

        for line in self.message_list:
            item = QStandardItem()
            item.setText(line)
            item.setEditable(False)
            model.appendRow(item)
        self.ui.lw_inbox.setModel(model)
        self.ui.lw_inbox.show()

    def load_subscribers(self):
        model = QStandardItemModel(self.ui.lw_my_subscribers)
        for i in self.my_subscribers:
            item = QStandardItem()
            item.setText(i)
            item.setEditable(False)
            model.appendRow(item)
        self.ui.lw_my_subscribers.setModel(model)
        self.ui.lw_my_subscribers.show()

    def on_UI_ready(self, data):
        data = data.split(":", 1)
        if data[0] == new_subscribe_request:
            model = QStandardItemModel(self.ui.lw_requests)
            item = QStandardItem()
            item.setText(data[1])
            item.setEditable(False)
            item.setData(data[1])
            model.appendRow(item)

            self.ui.lw_requests.setModel(model)
            self.ui.lw_requests.show()

        if data[0] == new_subscribe:
            model = QStandardItemModel(self.ui.lw_my_subscribers)
            item = QStandardItem()
            item.setText(data[1])
            item.setEditable(False)
            item.setData(data[1])
            model.appendRow(item)

            self.ui.lw_my_subscribers.setModel(model)
            self.ui.lw_my_subscribers.show()
            model = QStandardItemModel(self.ui.lw_requests)
            model.removeRow(index_selectedLine)
            self.ui.lw_requests.setModel(model)
            self.ui.lw_requests.show()

        if data[0] == new_subscribed_peer:
            model = QStandardItemModel(self.ui.lw_active_peers)
            item = QStandardItem()
            item.setText(data[1])
            item.setEditable(False)
            item.setData(data[1])
            model.appendRow(item)

            self.ui.lw_active_peers.setModel(model)
            self.ui.lw_active_peers.show()

        if data[0] == login:
            self.ui.login.setEnabled(False)
            self.ui.inbox.setEnabled(True)
            self.ui.blockusr.setEnabled(True)
            self.ui.requests.setEnabled(True)
            self.ui.peerlist.setEnabled(True)
            self.ui.home.setEnabled(True)

        if data[0] == new_user:
            if not data[1] == self.my_username:
                model = QStandardItemModel(self.ui.lw_peer_list)
                for k in self.peer_list.keys():
                    if not k == self.my_username:
                        item = QStandardItem()
                        item.setText(k)
                        item.setEditable(False)
                        item.setData(k)
                        model.appendRow(item)

                self.ui.lw_peer_list.setModel(model)
                self.ui.lw_peer_list.show()

        if data[0] == new_message:
            if self.clicked_message_user_name != "NULL" and data[1] == self.clicked_message_user_name:
                model = QStandardItemModel(self.ui.lw_inbox)
                for line in self.all_messages:
                    line = line.split(" ", 4)
                    if line[0] == self.my_username and line[1] == data[1]:
                        item = QStandardItem()
                        item.setText(line[2] + line[3] + " : " + line[0] + " => " + line[4])
                        item.setBackground(QColor("#666666"))
                        item.setSelectable(False)
                        item.setEditable(False)
                        model.appendRow(item)
                    elif line[0] == data[1] and line[1] == self.my_username:
                        item = QStandardItem()
                        item.setText(line[2] + line[3] + " : " + line[0] + " => " + line[4])
                        item.setEditable(False)
                        item.setSelectable(False)
                        model.appendRow(item)
                    else:
                        continue
                self.ui.lw_inbox.setModel(model)
                self.ui.lw_inbox.show()
                self.ui.btn_reload_messagebox.setEnabled(True)
            else:
                model = QStandardItemModel(self.ui.lw_inbox)
                for line in self.all_messages:
                    line = line.split(" ", 3)
                    if line[0] == self.my_username and line[1] not in self.message_list:
                        self.message_list.append(line[1])
                    elif line[0] not in self.message_list and line[0] != self.my_username:
                        self.message_list.append(line[0])

                for line in self.message_list:
                    item = QStandardItem()
                    item.setText(line)
                    item.setEditable(False)
                    if line == data[1]:
                        item.setBackground(QColor("#123d2f"))
                    model.appendRow(item)
                self.ui.lw_inbox.setModel(model)
                self.ui.lw_inbox.show()

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
        for i in self.my_subscribers:
            peer = self.peer_list.get(i, "NULL")
            if peer != "NULL":
                s = socket.socket()
                print(peer[0])
                print(peer[1])
                s.connect((peer[0], int(peer[1])))
                s.send(self.USRString.encode())
                time.sleep(1)
                message = "PSH " + blog_text
                s.send(message.encode())
                s.close()
            else:
                print("NULL VAR")

    def get_my_blogs(self):
        fid = open("app_data/" + self.my_username + ".txt", 'r')
        model = QStandardItemModel(self.ui.lw_blogs)
        self.i = 0
        for line in fid:
            item = QStandardItem()
            item.setText(line)
            item.setEditable(False)
            if self.i == 0:
                item.setBackground(QColor("#666666"))
            model.appendRow(item)
            self.i = self.i + 1
        fid.close()
        self.ui.lw_blogs.setModel(model)
        self.ui.lw_blogs.show()

    def peer_list_on_click(self):
        self.clicked_user_name = self.ui.lw_peer_list.selectedIndexes()[0].data()
        if self.peer_list[self.clicked_user_name][5] != "OFF":
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
        else:
            self.ui.btn_subscribe_user.setText("Offline")
            self.ui.btn_block_user.setText("Offline")

    def subscribe_user(self):
        peer = self.peer_list.get(self.clicked_user_name, "NULL")
        if peer != "NULL":
            self.ui.btn_subscribe_user.setText("Beklemede")
            s = socket.socket()
            print(peer[0])
            print(peer[1])
            s.connect((peer[0], int(peer[1])))
            s.send(self.USRString.encode())
            time.sleep(1)
            print(self.peer_list)
            message = "SBS"
            s.send(message.encode())
            s.close()
            fid = open("app_data/sended_subscribe_request.txt", "a+")
            fid.write(self.clicked_user_name + "\n")
            fid.close()
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
            s.send(self.USRString.encode())
            time.sleep(1)
            message = "BLU"
            s.send(message.encode())
            s.close()
            self.black_list.append(self.clicked_user_name)
            self.ui.btn_block_user.setText("Engellendi")
        else:
            print("NULL VAR")

    def reload_messagebox(self):
        self.load_lasted_messages()
        self.ui.btn_reload_messagebox.setEnabled(False)
        self.clicked_message_user_name = "NULL"

    def messagebox_on_click(self):
        if not self.ui.btn_reload_messagebox.isEnabled():
            self.clicked_message_user_name = self.ui.lw_inbox.selectedIndexes()[0].data()
        model = QStandardItemModel(self.ui.lw_inbox)
        for line in self.all_messages:
            line = line.split(" ", 4)
            if line[0] == self.my_username and line[1] == self.clicked_message_user_name:
                item = QStandardItem()
                item.setText(line[2] + line[3] + " : " + line[0] + " => " + line[4])
                item.setBackground(QColor("#666666"))
                item.setSelectable(False)
                item.setEditable(False)
                model.appendRow(item)
            elif line[0] == self.clicked_message_user_name and line[1] == self.my_username:
                item = QStandardItem()
                item.setText(line[2] + line[3] + " : " + line[0] + " => " + line[4])
                item.setEditable(False)
                item.setSelectable(False)
                model.appendRow(item)
            else:
                continue
        self.ui.lw_inbox.setModel(model)
        self.ui.lw_inbox.show()
        self.ui.btn_reload_messagebox.setEnabled(True)
        if self.ui.btn_reload_messagebox.isEnabled():
            self.message_to_selected_index = list(self.peer_list.keys()).index(self.clicked_message_user_name)
            self.ui.cb_message_to.setCurrentIndex(self.message_to_selected_index)

    def request_on_click(self):
        self.clicked_user_name = self.ui.lw_requests.selectedIndexes()[0].data()
        index_selectedLine = self.ui.lw_requests.selectedIndexes()[0]
        if self.clicked_user_name in self.black_list:
            self.ui.btn_accept_request.setText("Engellendi")
        else:
            self.ui.btn_accept_request.setEnabled(True)
            self.ui.btn_accept_request.pressed.connect(self.add_new_subscribe)

    def message_to_selected(self):
        self.message_to_selected_index = self.ui.cb_message_to.currentIndex()

    def add_new_subscribe(self):
        print("bastın")
        self.my_subscribers.append(self.clicked_user_name)
        index = self.my_subscribe_request.index(self.clicked_user_name)
        del self.my_subscribe_request[index]
        print(self.clicked_user_name)
        refresh_ui_queue.put(new_subscribe + ":" + self.clicked_user_name)
        peer = self.peer_list.get(self.clicked_user_name, "NULL")
        print(peer)
        fid = open("app_data/my_subscribers.txt", "a+")
        fid.write(str(self.clicked_user_name) + "\n")
        fid.close()
        fid = open("app_data/my_subscribe_request.txt", "w+")
        d = fid.readlines()
        for i in d:
            if i != self.clicked_user_name:
                fid.write(i + "\n")
        fid.close()
        s = socket.socket()
        s.connect((peer[0], int(peer[1])))
        s.send(self.USRString.encode())
        time.sleep(1)
        s.send("SBO".encode())
        s.close()

    def send_message(self):
        peer = self.peer_list.get(list(self.peer_list.keys())[self.message_to_selected_index], "NULL")
        if peer != "NULL":
            s = socket.socket()
            print(peer[0])
            print(peer[1])
            s.connect((peer[0], int(peer[1])))
            s.send(self.USRString.encode())
            time.sleep(1)
            message_parameters = self.my_username + " " + list(self.peer_list.keys())[
                self.message_to_selected_index] + " " + str(datetime.now()) + " " + self.ui.et_write_msg.toPlainText()
            message = "MSG " + message_parameters
            s.send(message.encode())
            s.close()
            refresh_ui_queue.put(new_message + ":" + list(self.peer_list.keys())[self.message_to_selected_index])
            self.all_messages.append(message_parameters)
            self.ui.et_write_msg.setPlainText("")
            fid = open("app_data/messages.txt", "a+")
            fid.write(message[4:] + "\n")
            fid.close()
        else:
            print("NULL VAR")

    def run(self):
        self.show()
        self.qt_app.exec_()


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


class ServerThread(threading.Thread):
    def __init__(self, s, my_username, my_ip, my_port, my_hash, my_type, connections, logger_queue, peer_list,
                 my_subscribers, black_list,
                 my_subscribe_request, sended_subscribe_request, subscribed_peers,
                 peer_list_that_block_me, all_messages):
        threading.Thread.__init__(self)
        self.s = s
        self.my_username = my_username
        self.my_ip = my_ip
        self.my_port = my_port
        self.my_hash = my_hash
        self.my_type = my_type
        self.connections = connections
        self.logger_queue = logger_queue
        self.peer_list = peer_list
        self.my_subscribers = my_subscribers
        self.black_list = black_list
        self.my_subscribe_request = my_subscribe_request
        self.sended_subscribe_request = sended_subscribe_request
        self.subscribed_peers = subscribed_peers
        self.peer_list_that_block_me = peer_list_that_block_me
        self.all_messages = all_messages
        self.connection_id = 0

    def run(self):
        print("server thread running")
        while True:
            connection, addr = self.s.accept()
            message_queue = queue.Queue()
            terminateThread = False
            server_reader_thread = ReaderThread(self.my_username, connection, addr,
                                                str(self.connection_id) + '.ReaderThread', self.connections,
                                                self.logger_queue, message_queue, self.peer_list, terminateThread,
                                                self.my_subscribers,
                                                self.black_list, self.my_subscribe_request,
                                                self.sended_subscribe_request, self.subscribed_peers,
                                                self.peer_list_that_block_me, self.all_messages)
            server_reader_thread.start()
            server_writer_thread = WriterThread(connection, addr, str(self.connection_id) + '.WriterThread',
                                                self.connections, self.logger_queue, message_queue,
                                                self.peer_list, terminateThread, self.my_username, self.my_ip,
                                                self.my_port, self.my_hash, self.my_type)
            server_writer_thread.start()
            self.connection_id = self.connection_id + 1
            print(threading.enumerate())


def load_lasted_files(my_username, peer_list, my_subscribers, my_subscribe_request, sended_subscribe_request,
                      subscribed_peers, black_list, peer_list_that_block_me, all_messages, my_blogs):
    fid = open("app_data/peer_list.txt", 'r')
    for line in fid:
        line = line.split(":", 1)
        splitted_line = yaml.load(line[1])
        peer_list[line[0]] = [splitted_line[0], splitted_line[1], splitted_line[2], splitted_line[3], splitted_line[4],
                              splitted_line[5]]
        print("peerlist in load" + str(peer_list))
    fid.close()

    fid = open("app_data/" + my_username + ".txt", 'r')
    for line in fid:
        my_blogs.append(line)
    fid.close()

    fid = open("app_data/messages.txt", 'r')
    for line in fid:
        all_messages.append(line)
    fid.close()

    fid = open("app_data/my_subscribers.txt", 'r')
    for line in fid:
        my_subscribers.append(line)
    fid.close()

    fid = open("app_data/sended_subscribe_request.txt", 'r')
    for line in fid:
        sended_subscribe_request.append(line)
    fid.close()

    fid = open("app_data/my_subscribe_request.txt", 'r')
    for line in fid:
        my_subscribe_request.append(line)
    fid.close()

    fid = open("app_data/subscribed_peers.txt", 'r')
    for line in fid:
        subscribed_peers.append(line)
    fid.close()

    fid = open("app_data/black_list.txt", 'r')
    for line in fid:
        black_list.append(line)
    fid.close()

    fid = open("app_data/peer_list_that_block_me.txt", 'r')
    for line in fid:
        peer_list_that_block_me.append(line)
    fid.close()


def create_app_data(my_username):
    open("app_data/" + my_username + ".txt", 'a').close()
    open("app_data/black_list.txt", 'a').close()
    open('app_data/messages.txt', 'a').close()
    open('app_data/my_subscribe_request.txt', 'a').close()
    open('app_data/peer_list_that_block_me.txt', 'a').close()
    open('app_data/my_subscribers.txt', 'a').close()
    open('app_data/peer_list.txt', 'a').close()
    open('app_data/sended_subscribe_request.txt', 'a').close()
    open('app_data/subscribed_peers.txt', 'a').close()


def create_rsa_pair(my_username):
    random_generator = Random.new().read

    # new key pair generation
    new_key = RSA.generate(2048, randfunc=random_generator)

    # get the public key and show it
    public_key = new_key.publickey()
    publicKey = public_key.exportKey("PEM")

    # get the private key and print
    # private key is given directly with the pair handle
    private_key = new_key

    privateKey = new_key.exportKey("PEM")

    # write to files
    f = open('peer_keys/' + my_username + '_private_key.txt', 'w')
    f.write(private_key.exportKey().decode())
    f.close()

    f = open('peer_keys/' + my_username + '_public_key.txt', 'w')
    f.write(public_key.exportKey().decode())
    f.close()


def main():
    global terminate_all_thread, refresh_ui_queue, public_key
    terminate_all_thread = False

    connections = {}
    peer_list = {}
    my_subscribers = []
    my_subscribe_request = []
    sended_subscribe_request = []
    subscribed_peers = []
    black_list = []
    peer_list_that_block_me = []
    message_list = []
    all_messages = []
    my_blogs = []
    logger_queue = queue.Queue()
    refresh_ui_queue = queue.Queue()
    signal.signal(signal.SIGINT, partial(signal_handler, peer_list))

    # my_ip = requests.get('http://ip.42.pl/raw').text
    my_ip = socket.gethostbyname(socket.gethostname())
    print(my_ip)
    my_port = 12344
    # my_username = str(uuid.NAMESPACE_DNS.hex)
    my_username = get_mac()
    my_type = "Y"
    # TODO: hash'i de kaydet
    m = hashlib.md5()
    m.update((my_username + " " + str(datetime.now())).encode())
    my_hash = m.hexdigest()

    if not os.path.isfile('peer_keys/' + my_username + '_private_key.txt') and not os.path.isfile(
            'peer_keys/' + my_username + '_public_key.txt'):
        create_rsa_pair(my_username)
    else:
        f = open('peer_keys/' + my_username + '_public_key.txt', 'r')
        public_key = RSA.import_key(f.read())

    if os.path.isfile('app_data/' + my_username + '.txt') and os.path.isfile('app_data/black_list.txt') \
            and os.path.isfile('app_data/messages.txt') and os.path.isfile('app_data/my_subscribe_request.txt') \
            and os.path.isfile('app_data/my_subscribers.txt') and os.path.isfile('app_data/peer_list.txt') \
            and os.path.isfile('app_data/peer_list_that_block_me.txt') and os.path.isfile(
        'app_data/sended_subscribe_request.txt') \
            and os.path.isfile('app_data/subscribed_peers.txt'):
        load_lasted_files(my_username, peer_list, my_subscribers, my_subscribe_request, sended_subscribe_request,
                          subscribed_peers, black_list, peer_list_that_block_me, all_messages, my_blogs)
    else:
        create_app_data(my_username)

    s = socket.socket()
    host = "0.0.0.0"
    port = 12344
    s.bind((host, port))
    s.listen()

    logger_thread = LoggerThread(logger_queue).start()

    new_peer_thread = New_Peer_Thread(peer_list, my_ip, my_port, my_username, my_type, my_hash)
    new_peer_thread.start()

    server_thread = ServerThread(s, my_username, my_ip, my_port, my_hash, my_type, connections, logger_queue,
                                 peer_list, my_subscribers, black_list,
                                 my_subscribe_request, sended_subscribe_request, subscribed_peers,
                                 peer_list_that_block_me, all_messages)
    server_thread.start()

    app = QtWidgets.QApplication(sys.argv)
    qt_and_client = QtSideAndClient(connections, logger_queue, peer_list, my_ip, my_port,
                                    my_username, my_type, my_subscribers, my_subscribe_request,
                                    subscribed_peers, black_list,
                                    sended_subscribe_request, peer_list_that_block_me, my_hash, message_list,
                                    my_blogs, all_messages)
    qt_and_client.run()


if __name__ == "__main__":
    main()
