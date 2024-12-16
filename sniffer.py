"""
@file: sniffer.py
@breif: Main file of Network Sniffer
@author: Wu Maojia
@update: 2024.12.16
"""
import sys
import pickle
import datetime

from scapy.all import sniff, get_if_list, conf, wrpcap, rdpcap

from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidgetItem, QMessageBox, QFileDialog
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QColor

from ui import Ui_MainWindow


class PacketSniffer(QThread):
    packet_captured = pyqtSignal(object)  # Define signal to pass captured packet object

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.sniffing = True

    def run(self):
        # Start packet capture, use stop_filter as a stop flag
        sniff(iface=self.iface, prn=self.handle_packet, stop_filter=lambda x: not self.sniffing)

    def handle_packet(self, packet):
        # Emit signal if conditions are met
        self.packet_captured.emit(packet)

    def stop(self):
        self.sniffing = False  # Terminate packet capture
        self.quit()


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()

        self.setupUi(self)

        # Initialize variables
        self.ifaces = []
        self.iface_aliases = []
        self.iface_packets = {}

        self.filter_protocol = None
        self.filter_src = None
        self.filter_dst = None

        self.reassembleIP = True if self.yesReassembleRadioButton.isChecked() else False

        self.protocol_colors = {
            'TCP': QColor(255, 228, 196),
            'UDP': QColor(217, 217, 243),
            'DNS': QColor(204, 255, 204),
            'ICMP': QColor(255, 204, 204),
            'Other': QColor(255, 255, 204)
        }

        # Initialize buttons
        self.startButton.clicked.connect(self.start_sniffing)
        self.stopButton.clicked.connect(self.stop_sniffing)
        self.filterButton.clicked.connect(self.filter)
        self.yesReassembleRadioButton.toggled.connect(self.on_reassemble_radio_button_toggled)
        self.noReassembleRadioButton.toggled.connect(self.on_reassemble_radio_button_toggled)
        self.clearButton.clicked.connect(self.clear)
        self.saveButton.clicked.connect(self.save)
        self.loadButton.clicked.connect(self.load)

        self.stopButton.setEnabled(False)

        # Initialize network interface list
        for iface_name, iface_obj in conf.ifaces.items():
            self.ifaces.append(iface_name)
            self.iface_aliases.append(iface_name + ' (' + iface_obj.name + ')')
            self.iface_packets[iface_name] = []

        self.networkInterfacesComboBox.addItems(self.iface_aliases)
        self.networkInterfacesComboBox.currentIndexChanged.connect(self.switch_iface)

        # Initialize Packet List, default to the first network interface
        self.packetTableWidget.setColumnCount(5)  # reset table header
        self.packetTableWidget.setHorizontalHeaderLabels(["Time", "Protocol", "Source", "Destination", "Length"])
        self.packetTableWidget.setColumnWidth(1, 500)
        self.packetTableWidget.setColumnWidth(4, 100)
        self.switch_iface(0)

    def switch_iface(self, index):
        self.packetDetailsTextEdit.clear()  # clear packet details

        # clear packet table but keep the header
        self.packetTableWidget.clearContents()
        self.packetTableWidget.setRowCount(0)

        # show each packet in the table
        for packet in self.iface_packets[self.ifaces[index]]:
            self.show_filtered_packet(packet)

    def filter(self):
        self.filter_protocol = self.protocolLineEdit.text()
        self.filter_src = self.sourceLineEdit.text()
        self.filter_dst = self.destinationLineEdit.text()
        self.switch_iface(self.networkInterfacesComboBox.currentIndex())    # Refresh Packet List

    def clear(self):
        selected_iface = self.ifaces[self.networkInterfacesComboBox.currentIndex()]
        self.iface_packets[selected_iface].clear()
        self.switch_iface(self.networkInterfacesComboBox.currentIndex())
        self.packetDetailsTextEdit.clear()

    def start_sniffing(self):
        # Get the user-selected network interface and filter conditions
        selected_iface = self.ifaces[self.networkInterfacesComboBox.currentIndex()]

        # Create and start the packet capture thread
        self.sniffer_thread = PacketSniffer(iface=selected_iface)
        self.sniffer_thread.packet_captured.connect(self.process_packet)  # Connect signal to processing function
        self.sniffer_thread.start()

        # Update button and option states
        self.startButton.setEnabled(False)
        self.stopButton.setEnabled(True)
        self.networkInterfacesComboBox.setEnabled(False)
        self.yesReassembleRadioButton.setEnabled(False)
        self.noReassembleRadioButton.setEnabled(False)

    def stop_sniffing(self):
        # Stop the packet capture thread
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait(3000)  # Wait up to 3 seconds
            if self.sniffer_thread.isRunning():
                reply = QMessageBox.question(None, 'Warning', 'Failed to stop the sniffer thread! Do you want to force it to terminate?',
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    
                # Perform actions based on user response
                if reply == QMessageBox.Yes:
                    self.sniffer_thread.terminate()
                    self.sniffer_thread.wait(3000)  # Wait up to 3 seconds
                    if self.sniffer_thread.isRunning():
                        QMessageBox.Warning(None, 'Warning', 'Failed to forcefully terminate the sniffer thread!')
                        return
                else:
                    return

        # Update button and option states
        self.startButton.setEnabled(True)
        self.stopButton.setEnabled(False)
        self.networkInterfacesComboBox.setEnabled(True)
        self.yesReassembleRadioButton.setEnabled(True)
        self.noReassembleRadioButton.setEnabled(True)

    def process_packet(self, packet):
        # Update iface_packets
        selected_iface = self.ifaces[self.networkInterfacesComboBox.currentIndex()]
        self.iface_packets[selected_iface].append(packet)

        self.show_filtered_packet(packet)

    def get_last_main_layer(self, packet):
        current_layer = packet
        last_main_layer = None
        while current_layer:
            if current_layer.name not in ["Padding", "Raw"]:
                last_main_layer = current_layer
            current_layer = current_layer.payload
        return last_main_layer

    def show_filtered_packet(self, packet):
        protocol = self.get_last_main_layer(packet).name  # Protocol type

        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            src = ip_layer.src  # Source IP address
            dst = ip_layer.dst  # Destination IP address
        else:
            src = packet.src if hasattr(packet, 'src') else 'N/A'  # Source MAC address
            dst = packet.dst if hasattr(packet, 'dst') else 'N/A'  # Destination MAC address
        
        # Filter packets based on user input
        if self.filter_protocol and self.filter_protocol.lower() not in protocol.lower():
            return
        if self.filter_src and self.filter_src != src:
            return
        if self.filter_dst and self.filter_dst != dst:
            return

        self.show_packet(packet)

    def show_packet(self, packet):
        # Process each captured packet and update the UI
        timestamp = float(packet.time)
        readable_time = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        protocol = self.get_last_main_layer(packet).name  # Protocol type

        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            src = ip_layer.src  # Source IP address
            dst = ip_layer.dst  # Destination IP address
        else:
            src = packet.src if hasattr(packet, 'src') else 'N/A'  # Source MAC address
            dst = packet.dst if hasattr(packet, 'dst') else 'N/A'  # Destination MAC address

        length = len(packet)  # Packet length

        # Display summary information in the table
        row_position = self.packetTableWidget.rowCount()
        self.packetTableWidget.insertRow(row_position)

        # Set color
        color = self.protocol_colors.get(protocol, self.protocol_colors['Other'])
        item_contents = [readable_time, protocol, src, dst, str(length)]
        for col in range(5):
            item = QTableWidgetItem(item_contents[col])
            item.setBackground(color)
            self.packetTableWidget.setItem(row_position, col, item)

        # Add double-click event to each row to display detailed information
        self.packetTableWidget.itemClicked.connect(self.show_packet_details)

    def show_packet_details(self, item):
        row = item.row()

        # Display detailed packet information
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

    def save(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save File", "", "PCAP Files (*.pcap);;All Files (*)", options=options)
        
        if file_name:
            selected_iface = self.ifaces[self.networkInterfacesComboBox.currentIndex()]
            wrpcap(file_name, self.iface_packets[selected_iface])

    def load(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Load File", "", "PCAP Files (*.pcap);;All Files (*)", options=options)

        if file_name:
            packets = rdpcap(file_name)
            selected_iface = self.ifaces[self.networkInterfacesComboBox.currentIndex()]
            for packet in packets:
                self.iface_packets[selected_iface].append(packet)
                self.show_filtered_packet(packet)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())