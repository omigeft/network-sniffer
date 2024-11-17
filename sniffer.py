"""
@file: sniffer.py
@breif: Main file of Network Sniffer
@author: Wu Maojia
@update: 2024.11.17
"""
import sys

from scapy.all import sniff, get_if_list, conf

from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QMessageBox
from PyQt5.QtCore import Qt, pyqtSignal, QThread

from ui import Ui_MainWindow


class PacketSniffer(QThread):
    packet_captured = pyqtSignal(object)  # 定义信号，传递抓到的数据包对象

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.sniffing = True

    def run(self):
        # 启动抓包，使用 stop_filter 作为停止标志
        sniff(iface=self.iface, prn=self.handle_packet, stop_filter=lambda x: not self.sniffing)

    def handle_packet(self, packet):
        # 如果符合条件则发送信号
        self.packet_captured.emit(packet)

    def stop(self):
        self.sniffing = False  # 终止抓包
        self.quit()


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()

        self.setupUi(self)

        # 初始化变量
        self.ifaces = []
        self.iface_aliases = []
        self.iface_packets = {}

        self.filter_protocol = None
        self.filter_src = None
        self.filter_dst = None

        self.reassembleIP = True if self.yesReassembleRadioButton.isChecked() else False

        # 初始化按钮
        self.startButton.clicked.connect(self.start_sniffing)
        self.stopButton.clicked.connect(self.stop_sniffing)
        self.filterButton.clicked.connect(self.filter)
        self.yesReassembleRadioButton.toggled.connect(self.on_reassemble_radio_button_toggled)
        self.noReassembleRadioButton.toggled.connect(self.on_reassemble_radio_button_toggled)

        self.stopButton.setEnabled(False)

        # 初始化网卡列表
        for iface_name, iface_obj in conf.ifaces.items():
            self.ifaces.append(iface_name)
            self.iface_aliases.append(iface_name + ' (' + iface_obj.name + ')')
            self.iface_packets[iface_name] = []

        self.networkInterfacesComboBox.addItems(self.iface_aliases)
        self.networkInterfacesComboBox.currentIndexChanged.connect(self.switch_iface)

        # 初始化Packet List，默认选择第一个网卡
        self.switch_iface(0)

    def switch_iface(self, index):
        self.packetDetailsTextEdit.clear()  # clear packet details

        self.packetTableWidget.clear()  # clear packet table
        self.packetTableWidget.setColumnCount(4)  # reset table header
        self.packetTableWidget.setRowCount(0)  # reset row number of table
        self.packetTableWidget.setHorizontalHeaderLabels(["Protocol", "Source", "Destination", "Length"])

        # show each packet in the table
        for packet in self.iface_packets[self.ifaces[index]]:
            protocol = packet.name  # 协议类型
            src = packet.src if hasattr(packet, 'src') else 'N/A'  # 源地址
            dst = packet.dst if hasattr(packet, 'dst') else 'N/A'  # 目的地址
            
            # 根据用户输入的过滤条件筛选数据包
            if self.filter_protocol and self.filter_protocol.lower() not in protocol.lower():
                continue
            if self.filter_src and self.filter_src != src:
                continue
            if self.filter_dst and self.filter_dst != dst:
                continue

            self.show_packet(packet)

    def filter(self):
        self.filter_protocol = self.protocolLineEdit.text()
        self.filter_src = self.sourceLineEdit.text()
        self.filter_dst = self.destinationLineEdit.text()
        self.switch_iface(self.networkInterfacesComboBox.currentIndex())    # 刷新Packet List

    def clear(self):
        self.iface_packets[self.ifaces[index]].clear()
        self.switch_iface(self.networkInterfacesComboBox.currentIndex())
        self.packetDetailsTextEdit.clear()

    def start_sniffing(self):
        # 获取用户选择的网卡和过滤条件
        selected_iface = self.ifaces[self.networkInterfacesComboBox.currentIndex()]
        print(selected_iface)
        filter_protocol = self.protocolLineEdit.text()
        filter_src = self.sourceLineEdit.text()
        filter_dst = self.destinationLineEdit.text()

        # 创建并启动抓包线程
        self.sniffer_thread = PacketSniffer(iface=selected_iface)
        self.sniffer_thread.packet_captured.connect(self.process_packet)  # 连接信号到处理函数
        self.sniffer_thread.start()

        # 更新按钮和选项状态
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)
        self.networkInterfacesComboBox.setEnabled(False)
        self.yesReassembleRadioButton.setEnabled(False)
        self.noReassembleRadioButton.setEnabled(False)

    def stop_sniffing(self):
        # 停止抓包线程
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait(3000)  # 最多等待3秒
            if self.sniffer_thread.isRunning():
                reply = QMessageBox.question(None, 'Warning', 'Failed to stop the sniffer thread! Do you want to force it to terminate?',
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    
                # 根据用户的回答执行相应操作
                if reply == QMessageBox.Yes:
                    self.sniffer_thread.terminate()
                    self.sniffer_thread.wait(3000)  # 最多等待3秒
                    if self.sniffer_thread.isRunning():
                        QMessageBox.Warning(None, 'Warning', 'Failed to forcefully terminate the sniffer thread!')
                        return
                else:
                    return

        # 更新按钮和选项状态
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)
        self.networkInterfacesComboBox.setEnabled(True)
        self.yesReassembleRadioButton.setEnabled(True)
        self.noReassembleRadioButton.setEnabled(True)

    def process_packet(self, packet):
        # 更新 iface_packets
        selected_iface = self.ifaces[self.networkInterfacesComboBox.currentIndex()]
        self.iface_packets[selected_iface].append(packet)

        self.show_packet(packet)

    def show_packet(self, packet):
        # 处理每个抓到的数据包并更新界面
        protocol = packet.name  # 协议类型
        src = packet.src if hasattr(packet, 'src') else 'N/A'  # 源地址
        dst = packet.dst if hasattr(packet, 'dst') else 'N/A'  # 目的地址
        length = len(packet)  # 数据包长度

        # 在表格中显示简要信息
        row_position = self.packetTableWidget.rowCount()
        self.packetTableWidget.insertRow(row_position)
        self.packetTableWidget.setItem(row_position, 0, QTableWidgetItem(protocol))
        self.packetTableWidget.setItem(row_position, 1, QTableWidgetItem(src))
        self.packetTableWidget.setItem(row_position, 2, QTableWidgetItem(dst))
        self.packetTableWidget.setItem(row_position, 3, QTableWidgetItem(str(length)))

        # 为每行添加双击事件，显示详细信息
        self.packetTableWidget.itemClicked.connect(self.show_packet_details)

    def show_packet_details(self, item):
        row = item.row()

        # 显示详细数据包信息
        selected_iface = self.ifaces[self.networkInterfacesComboBox.currentIndex()]
        packet = self.iface_packets[selected_iface][row]
        self.packetDetailsTextEdit.setPlainText(str(packet.show(dump=True)))

    def on_reassemble_radio_button_toggled(self, checked):
        sender = self.sender()
        if checked:
            if sender == self.yesReassembleRadioButton:
                self.reassembleIP = True
            elif sender == self.noReassembleRadioButton:
                self.reassembleIP = False


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())