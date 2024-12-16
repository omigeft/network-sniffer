# Network Sniffer

### Software Objective

Design and implement a sniffer tool capable of capturing and analyzing data flowing through a specified network interface. The specific technical requirements are as follows:

1. Allow the user to select a network interface if multiple interfaces are available on the host.

2. Filter and search data frames (packets or segments) based on protocol type, source address, and destination address.

3. Implement IP fragmentation reassembly.

4. Support saving and loading of analysis results.

5. Parse Ethernet frames, IPv4, TCP, UDP, HTTP, ARP, and ICMP protocol data.

### Submission Requirements:

1. A functional sniffer tool (including executable files, source code, and usage/configuration instructions).

2. A technical report on the sniffer tool (covering design, implementation, and testing phases).

### Environment Setup

Visit [https://npcap.com/](https://npcap.com/) to download and install Npcap. During installation, ensure that the option **Install Npcap in WinPcap API-compatible Mode** is checked. This ensures that Npcap's API is compatible with WinPcap, enabling Scapy to function correctly.

Install the Python development environment. The software has been tested with Python version 3.10.

Run the following command in the terminal to install the required Python dependencies:

```shell
pip install -r requirements.txt
```

### Execution

Run the following command in the terminal to start the program:

```shell
python sniffer.py
```

### UI Redesign

To redesign the user interface, open `sniffer.ui` using Qt Designer. Then, run the following command in the terminal to convert the `.ui` file into a `.py` file:

```bash
pyuic5 -x sniffer.ui -o ui.py
```

### UI Demo

<img src="./assets/sniffer.png"/>

### License

This project is licensed under the terms of the [MIT license](./LICENSE).