# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'mainwindow.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(662, 510)
        self.centralWidget = QtWidgets.QWidget(MainWindow)
        self.centralWidget.setObjectName("centralWidget")
        self.tabWidget_2 = QtWidgets.QTabWidget(self.centralWidget)
        self.tabWidget_2.setGeometry(QtCore.QRect(0, 10, 661, 441))
        self.tabWidget_2.setMinimumSize(QtCore.QSize(661, 411))
        self.tabWidget_2.setMaximumSize(QtCore.QSize(661, 450))
        self.tabWidget_2.setObjectName("tabWidget_2")
        self.home = QtWidgets.QWidget()
        self.home.setObjectName("home")
        self.label_7 = QtWidgets.QLabel(self.home)
        self.label_7.setGeometry(QtCore.QRect(460, 20, 141, 16))
        self.label_7.setObjectName("label_7")
        self.label_6 = QtWidgets.QLabel(self.home)
        self.label_6.setGeometry(QtCore.QRect(20, 20, 47, 13))
        self.label_6.setObjectName("label_6")
        self.et_publish_blog = QtWidgets.QPlainTextEdit(self.home)
        self.et_publish_blog.setGeometry(QtCore.QRect(20, 310, 331, 31))
        self.et_publish_blog.setObjectName("et_publish_blog")
        self.btn_publish_blog = QtWidgets.QPushButton(self.home)
        self.btn_publish_blog.setGeometry(QtCore.QRect(370, 310, 71, 31))
        self.btn_publish_blog.setObjectName("btn_publish_blog")
        self.horizontalLayoutWidget_4 = QtWidgets.QWidget(self.home)
        self.horizontalLayoutWidget_4.setGeometry(QtCore.QRect(460, 40, 161, 261))
        self.horizontalLayoutWidget_4.setObjectName("horizontalLayoutWidget_4")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_4)
        self.horizontalLayout_5.setContentsMargins(11, 11, 11, 11)
        self.horizontalLayout_5.setSpacing(6)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.lw_active_peers = QtWidgets.QListView(self.horizontalLayoutWidget_4)
        self.lw_active_peers.setEnabled(True)
        self.lw_active_peers.setObjectName("lw_active_peers")
        self.horizontalLayout_5.addWidget(self.lw_active_peers)
        self.horizontalLayoutWidget_5 = QtWidgets.QWidget(self.home)
        self.horizontalLayoutWidget_5.setGeometry(QtCore.QRect(20, 40, 421, 261))
        self.horizontalLayoutWidget_5.setObjectName("horizontalLayoutWidget_5")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_5)
        self.horizontalLayout_6.setContentsMargins(11, 11, 11, 11)
        self.horizontalLayout_6.setSpacing(6)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.lw_blogs = QtWidgets.QListView(self.horizontalLayoutWidget_5)
        self.lw_blogs.setObjectName("lw_blogs")
        self.horizontalLayout_6.addWidget(self.lw_blogs)
        self.btn_get_my_blog = QtWidgets.QPushButton(self.home)
        self.btn_get_my_blog.setGeometry(QtCore.QRect(480, 370, 131, 31))
        self.btn_get_my_blog.setObjectName("btn_get_my_blog")
        self.btn_get_peer_blog = QtWidgets.QPushButton(self.home)
        self.btn_get_peer_blog.setEnabled(False)
        self.btn_get_peer_blog.setGeometry(QtCore.QRect(480, 310, 131, 31))
        self.btn_get_peer_blog.setObjectName("btn_get_peer_blog")
        self.btn_get_lasted_15_blog = QtWidgets.QPushButton(self.home)
        self.btn_get_lasted_15_blog.setGeometry(QtCore.QRect(480, 340, 131, 31))
        self.btn_get_lasted_15_blog.setObjectName("btn_get_lasted_15_blog")
        self.tabWidget_2.addTab(self.home, "")
        self.peerlist = QtWidgets.QWidget()
        self.peerlist.setObjectName("peerlist")
        self.label_8 = QtWidgets.QLabel(self.peerlist)
        self.label_8.setGeometry(QtCore.QRect(20, 20, 171, 16))
        self.label_8.setObjectName("label_8")
        self.btn_subscribe_user = QtWidgets.QPushButton(self.peerlist)
        self.btn_subscribe_user.setEnabled(False)
        self.btn_subscribe_user.setGeometry(QtCore.QRect(400, 40, 151, 23))
        self.btn_subscribe_user.setObjectName("btn_subscribe_user")
        self.btn_block_user = QtWidgets.QPushButton(self.peerlist)
        self.btn_block_user.setEnabled(False)
        self.btn_block_user.setGeometry(QtCore.QRect(400, 70, 151, 23))
        self.btn_block_user.setObjectName("btn_block_user")
        self.horizontalLayoutWidget_6 = QtWidgets.QWidget(self.peerlist)
        self.horizontalLayoutWidget_6.setGeometry(QtCore.QRect(20, 40, 351, 271))
        self.horizontalLayoutWidget_6.setObjectName("horizontalLayoutWidget_6")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_6)
        self.horizontalLayout_7.setContentsMargins(11, 11, 11, 11)
        self.horizontalLayout_7.setSpacing(6)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.lw_peer_list = QtWidgets.QListView(self.horizontalLayoutWidget_6)
        self.lw_peer_list.setObjectName("lw_peer_list")
        self.horizontalLayout_7.addWidget(self.lw_peer_list)
        self.tabWidget_2.addTab(self.peerlist, "")
        self.inbox = QtWidgets.QWidget()
        self.inbox.setObjectName("inbox")
        self.cb_message_to = QtWidgets.QComboBox(self.inbox)
        self.cb_message_to.setGeometry(QtCore.QRect(360, 230, 251, 22))
        self.cb_message_to.setObjectName("cb_message_to")
        self.label_11 = QtWidgets.QLabel(self.inbox)
        self.label_11.setGeometry(QtCore.QRect(20, 20, 101, 16))
        self.label_11.setObjectName("label_11")
        self.label_10 = QtWidgets.QLabel(self.inbox)
        self.label_10.setGeometry(QtCore.QRect(360, 20, 47, 13))
        self.label_10.setObjectName("label_10")
        self.label_9 = QtWidgets.QLabel(self.inbox)
        self.label_9.setGeometry(QtCore.QRect(360, 210, 47, 13))
        self.label_9.setObjectName("label_9")
        self.btn_send_message = QtWidgets.QPushButton(self.inbox)
        self.btn_send_message.setGeometry(QtCore.QRect(540, 260, 75, 23))
        self.btn_send_message.setObjectName("btn_send_message")
        self.horizontalLayoutWidget_7 = QtWidgets.QWidget(self.inbox)
        self.horizontalLayoutWidget_7.setGeometry(QtCore.QRect(20, 40, 331, 261))
        self.horizontalLayoutWidget_7.setObjectName("horizontalLayoutWidget_7")
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_7)
        self.horizontalLayout_8.setContentsMargins(11, 11, 11, 11)
        self.horizontalLayout_8.setSpacing(6)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.lw_inbox = QtWidgets.QListView(self.horizontalLayoutWidget_7)
        self.lw_inbox.setObjectName("lw_inbox")
        self.horizontalLayout_8.addWidget(self.lw_inbox)
        self.horizontalLayoutWidget_8 = QtWidgets.QWidget(self.inbox)
        self.horizontalLayoutWidget_8.setGeometry(QtCore.QRect(360, 40, 251, 161))
        self.horizontalLayoutWidget_8.setObjectName("horizontalLayoutWidget_8")
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_8)
        self.horizontalLayout_9.setContentsMargins(11, 11, 11, 11)
        self.horizontalLayout_9.setSpacing(6)
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        self.et_write_msg = QtWidgets.QPlainTextEdit(self.horizontalLayoutWidget_8)
        self.et_write_msg.setObjectName("et_write_msg")
        self.horizontalLayout_9.addWidget(self.et_write_msg)
        self.btn_reload_messagebox = QtWidgets.QPushButton(self.inbox)
        self.btn_reload_messagebox.setEnabled(False)
        self.btn_reload_messagebox.setGeometry(QtCore.QRect(280, 320, 75, 23))
        self.btn_reload_messagebox.setObjectName("btn_reload_messagebox")
        self.tabWidget_2.addTab(self.inbox, "")
        self.blockusr = QtWidgets.QWidget()
        self.blockusr.setObjectName("blockusr")
        self.horizontalLayoutWidget_9 = QtWidgets.QWidget(self.blockusr)
        self.horizontalLayoutWidget_9.setGeometry(QtCore.QRect(30, 50, 591, 141))
        self.horizontalLayoutWidget_9.setObjectName("horizontalLayoutWidget_9")
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_9)
        self.horizontalLayout_10.setContentsMargins(11, 11, 11, 11)
        self.horizontalLayout_10.setSpacing(6)
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.lw_blocked_users = QtWidgets.QListView(self.horizontalLayoutWidget_9)
        self.lw_blocked_users.setObjectName("lw_blocked_users")
        self.horizontalLayout_10.addWidget(self.lw_blocked_users)
        self.label_12 = QtWidgets.QLabel(self.blockusr)
        self.label_12.setGeometry(QtCore.QRect(30, 20, 221, 16))
        self.label_12.setObjectName("label_12")
        self.btn_unblock_user = QtWidgets.QPushButton(self.blockusr)
        self.btn_unblock_user.setGeometry(QtCore.QRect(30, 210, 181, 23))
        self.btn_unblock_user.setObjectName("btn_unblock_user")
        self.tabWidget_2.addTab(self.blockusr, "")
        self.requests = QtWidgets.QWidget()
        self.requests.setObjectName("requests")
        self.horizontalLayoutWidget = QtWidgets.QWidget(self.requests)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(60, 40, 241, 281))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(11, 11, 11, 11)
        self.horizontalLayout.setSpacing(6)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lw_requests = QtWidgets.QListView(self.horizontalLayoutWidget)
        self.lw_requests.setObjectName("lw_requests")
        self.horizontalLayout.addWidget(self.lw_requests)
        self.btn_block_user_r = QtWidgets.QPushButton(self.requests)
        self.btn_block_user_r.setGeometry(QtCore.QRect(60, 340, 75, 23))
        self.btn_block_user_r.setObjectName("btn_block_user_r")
        self.btn_accept_request = QtWidgets.QPushButton(self.requests)
        self.btn_accept_request.setGeometry(QtCore.QRect(140, 340, 75, 23))
        self.btn_accept_request.setObjectName("btn_accept_request")
        self.horizontalLayoutWidget_2 = QtWidgets.QWidget(self.requests)
        self.horizontalLayoutWidget_2.setGeometry(QtCore.QRect(360, 40, 241, 281))
        self.horizontalLayoutWidget_2.setObjectName("horizontalLayoutWidget_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_2)
        self.horizontalLayout_2.setContentsMargins(11, 11, 11, 11)
        self.horizontalLayout_2.setSpacing(6)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.lw_my_subscribers = QtWidgets.QListView(self.horizontalLayoutWidget_2)
        self.lw_my_subscribers.setObjectName("lw_my_subscribers")
        self.horizontalLayout_2.addWidget(self.lw_my_subscribers)
        self.label_2 = QtWidgets.QLabel(self.requests)
        self.label_2.setGeometry(QtCore.QRect(360, 20, 201, 16))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.requests)
        self.label_3.setGeometry(QtCore.QRect(60, 20, 201, 16))
        self.label_3.setObjectName("label_3")
        self.tabWidget_2.addTab(self.requests, "")
        MainWindow.setCentralWidget(self.centralWidget)
        self.menuBar = QtWidgets.QMenuBar(MainWindow)
        self.menuBar.setGeometry(QtCore.QRect(0, 0, 662, 22))
        self.menuBar.setObjectName("menuBar")
        MainWindow.setMenuBar(self.menuBar)
        self.mainToolBar = QtWidgets.QToolBar(MainWindow)
        self.mainToolBar.setObjectName("mainToolBar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.mainToolBar)
        self.statusBar = QtWidgets.QStatusBar(MainWindow)
        self.statusBar.setObjectName("statusBar")
        MainWindow.setStatusBar(self.statusBar)

        self.retranslateUi(MainWindow)
        self.tabWidget_2.setCurrentIndex(2)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label_7.setText(_translate("MainWindow", "Aktif takip ettiklerim"))
        self.label_6.setText(_translate("MainWindow", "Yayınlar"))
        self.btn_publish_blog.setText(_translate("MainWindow", "Yayınla"))
        self.btn_get_my_blog.setText(_translate("MainWindow", "Kendi Yayınlarım"))
        self.btn_get_peer_blog.setText(_translate("MainWindow", "Seçili Yayını Getir"))
        self.btn_get_lasted_15_blog.setText(_translate("MainWindow", "Son Yayınlar"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.home), _translate("MainWindow", "Home"))
        self.label_8.setText(_translate("MainWindow", "Ağda olan peer\'ların listesi"))
        self.btn_subscribe_user.setText(_translate("MainWindow", "Abone Ol"))
        self.btn_block_user.setText(_translate("MainWindow", "Engelle"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.peerlist), _translate("MainWindow", "Network Peer List"))
        self.label_11.setText(_translate("MainWindow", "Gelen Kutusu"))
        self.label_10.setText(_translate("MainWindow", "Mesaj"))
        self.label_9.setText(_translate("MainWindow", "Kime"))
        self.btn_send_message.setText(_translate("MainWindow", "Yolla"))
        self.btn_reload_messagebox.setText(_translate("MainWindow", "Geri"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.inbox), _translate("MainWindow", "Inbox"))
        self.label_12.setText(_translate("MainWindow", "Engellenmiş Peer Listesi"))
        self.btn_unblock_user.setText(_translate("MainWindow", "Engelli Kaldır"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.blockusr), _translate("MainWindow", "Blocked Users"))
        self.btn_block_user_r.setText(_translate("MainWindow", "Engelle"))
        self.btn_accept_request.setText(_translate("MainWindow", "Onayla"))
        self.label_2.setText(_translate("MainWindow", "Bana abone olanlar"))
        self.label_3.setText(_translate("MainWindow", "Gelen istekler"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.requests), _translate("MainWindow", "Requests"))

