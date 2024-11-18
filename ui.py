# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'sniffer.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(2000, 1500)
        self.centralWidget = QtWidgets.QWidget(MainWindow)
        self.centralWidget.setObjectName("centralWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralWidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.networkInterfaceHorizontalLayout = QtWidgets.QHBoxLayout()
        self.networkInterfaceHorizontalLayout.setObjectName("networkInterfaceHorizontalLayout")
        self.networkInterfaceLabel = QtWidgets.QLabel(self.centralWidget)
        self.networkInterfaceLabel.setObjectName("networkInterfaceLabel")
        self.networkInterfaceHorizontalLayout.addWidget(self.networkInterfaceLabel)
        self.networkInterfacesComboBox = QtWidgets.QComboBox(self.centralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.networkInterfacesComboBox.sizePolicy().hasHeightForWidth())
        self.networkInterfacesComboBox.setSizePolicy(sizePolicy)
        self.networkInterfacesComboBox.setObjectName("networkInterfacesComboBox")
        self.networkInterfaceHorizontalLayout.addWidget(self.networkInterfacesComboBox)
        self.verticalLayout.addLayout(self.networkInterfaceHorizontalLayout)
        self.filterHorizontalLayout = QtWidgets.QHBoxLayout()
        self.filterHorizontalLayout.setObjectName("filterHorizontalLayout")
        self.protocolLineEdit = QtWidgets.QLineEdit(self.centralWidget)
        self.protocolLineEdit.setObjectName("protocolLineEdit")
        self.filterHorizontalLayout.addWidget(self.protocolLineEdit)
        self.sourceLineEdit = QtWidgets.QLineEdit(self.centralWidget)
        self.sourceLineEdit.setObjectName("sourceLineEdit")
        self.filterHorizontalLayout.addWidget(self.sourceLineEdit)
        self.destinationLineEdit = QtWidgets.QLineEdit(self.centralWidget)
        self.destinationLineEdit.setObjectName("destinationLineEdit")
        self.filterHorizontalLayout.addWidget(self.destinationLineEdit)
        self.summaryLineEdit = QtWidgets.QLineEdit(self.centralWidget)
        self.summaryLineEdit.setObjectName("summaryLineEdit")
        self.filterHorizontalLayout.addWidget(self.summaryLineEdit)
        self.filterButton = QtWidgets.QPushButton(self.centralWidget)
        self.filterButton.setObjectName("filterButton")
        self.filterHorizontalLayout.addWidget(self.filterButton)
        self.verticalLayout.addLayout(self.filterHorizontalLayout)
        self.reassembleHorizontalLayout = QtWidgets.QHBoxLayout()
        self.reassembleHorizontalLayout.setObjectName("reassembleHorizontalLayout")
        self.reassembleLabel = QtWidgets.QLabel(self.centralWidget)
        self.reassembleLabel.setObjectName("reassembleLabel")
        self.reassembleHorizontalLayout.addWidget(self.reassembleLabel)
        self.yesReassembleRadioButton = QtWidgets.QRadioButton(self.centralWidget)
        self.yesReassembleRadioButton.setChecked(True)
        self.yesReassembleRadioButton.setObjectName("yesReassembleRadioButton")
        self.reassembleHorizontalLayout.addWidget(self.yesReassembleRadioButton)
        self.noReassembleRadioButton = QtWidgets.QRadioButton(self.centralWidget)
        self.noReassembleRadioButton.setChecked(False)
        self.noReassembleRadioButton.setObjectName("noReassembleRadioButton")
        self.reassembleHorizontalLayout.addWidget(self.noReassembleRadioButton)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.reassembleHorizontalLayout.addItem(spacerItem)
        self.verticalLayout.addLayout(self.reassembleHorizontalLayout)
        self.startStopHorizontalLayout = QtWidgets.QHBoxLayout()
        self.startStopHorizontalLayout.setObjectName("startStopHorizontalLayout")
        self.startButton = QtWidgets.QPushButton(self.centralWidget)
        self.startButton.setObjectName("startButton")
        self.startStopHorizontalLayout.addWidget(self.startButton)
        self.stopButton = QtWidgets.QPushButton(self.centralWidget)
        self.stopButton.setObjectName("stopButton")
        self.startStopHorizontalLayout.addWidget(self.stopButton)
        self.verticalLayout.addLayout(self.startStopHorizontalLayout)
        self.packetListhorizontalLayout = QtWidgets.QHBoxLayout()
        self.packetListhorizontalLayout.setObjectName("packetListhorizontalLayout")
        self.packetListLabel = QtWidgets.QLabel(self.centralWidget)
        self.packetListLabel.setObjectName("packetListLabel")
        self.packetListhorizontalLayout.addWidget(self.packetListLabel)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.packetListhorizontalLayout.addItem(spacerItem1)
        self.clearButton = QtWidgets.QPushButton(self.centralWidget)
        self.clearButton.setObjectName("clearButton")
        self.packetListhorizontalLayout.addWidget(self.clearButton)
        self.verticalLayout.addLayout(self.packetListhorizontalLayout)
        self.packetTableWidget = QtWidgets.QTableWidget(self.centralWidget)
        self.packetTableWidget.setObjectName("packetTableWidget")
        self.packetTableWidget.setColumnCount(0)
        self.packetTableWidget.setRowCount(0)
        self.packetTableWidget.horizontalHeader().setDefaultSectionSize(250)
        self.verticalLayout.addWidget(self.packetTableWidget)
        self.packetDetailsLabel = QtWidgets.QLabel(self.centralWidget)
        self.packetDetailsLabel.setObjectName("packetDetailsLabel")
        self.verticalLayout.addWidget(self.packetDetailsLabel)
        self.packetDetailsTextEdit = QtWidgets.QPlainTextEdit(self.centralWidget)
        self.packetDetailsTextEdit.setReadOnly(True)
        self.packetDetailsTextEdit.setObjectName("packetDetailsTextEdit")
        self.verticalLayout.addWidget(self.packetDetailsTextEdit)
        self.saveLoadHorizontalLayout = QtWidgets.QHBoxLayout()
        self.saveLoadHorizontalLayout.setObjectName("saveLoadHorizontalLayout")
        self.saveButton = QtWidgets.QPushButton(self.centralWidget)
        self.saveButton.setObjectName("saveButton")
        self.saveLoadHorizontalLayout.addWidget(self.saveButton)
        self.loadButton = QtWidgets.QPushButton(self.centralWidget)
        self.loadButton.setObjectName("loadButton")
        self.saveLoadHorizontalLayout.addWidget(self.loadButton)
        self.verticalLayout.addLayout(self.saveLoadHorizontalLayout)
        MainWindow.setCentralWidget(self.centralWidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Network Sniffer"))
        self.networkInterfaceLabel.setText(_translate("MainWindow", "Network Interface: "))
        self.protocolLineEdit.setPlaceholderText(_translate("MainWindow", "Protocol (e.g. Ethernet)"))
        self.sourceLineEdit.setPlaceholderText(_translate("MainWindow", "Source IP (e.g. 192.168.1.1)"))
        self.destinationLineEdit.setPlaceholderText(_translate("MainWindow", "Destination IP (e.g. 192.168.1.2)"))
        self.summaryLineEdit.setPlaceholderText(_translate("MainWindow", "Summary (e.g. TCP)"))
        self.filterButton.setText(_translate("MainWindow", "Filter"))
        self.reassembleLabel.setText(_translate("MainWindow", "Reassemble IP Fragments:"))
        self.yesReassembleRadioButton.setText(_translate("MainWindow", "Yes"))
        self.noReassembleRadioButton.setText(_translate("MainWindow", "No"))
        self.startButton.setText(_translate("MainWindow", "Start"))
        self.stopButton.setText(_translate("MainWindow", "Stop"))
        self.packetListLabel.setText(_translate("MainWindow", "Packet List:"))
        self.clearButton.setText(_translate("MainWindow", "Clear"))
        self.packetDetailsLabel.setText(_translate("MainWindow", "Packet Details:"))
        self.saveButton.setText(_translate("MainWindow", "Save"))
        self.loadButton.setText(_translate("MainWindow", "Load"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
