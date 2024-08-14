# Packet Sniffer

A Python-based packet sniffer with a graphical user interface (GUI) built using Tkinter and Scapy. This tool allows you to capture network packets, filter them by protocol, IP address, and port number, and save or export the captured packets to various formats.

## Features

- **Packet Capture:** Capture network packets on a selected interface.
- **Filtering:** Filter packets by IP address, port number, content, and protocol (TCP, UDP, ICMP).
- **Protocol Statistics:** View real-time statistics of captured protocols.
- **Save and Export:** Save captured packets to a PCAP file or export summaries to CSV or JSON formats.
- **User-Friendly Interface:** Dark mode interface with easy-to-use controls.
- **Alerts:** Receive alerts when a specified packet count threshold is reached.

## Requirements

- Python 3.x
- Scapy
- Tkinter (usually included with Python installations)
- netifaces (for network interface selection)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/packet-sniffer.git
   cd packet-sniffer
   ```

2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python packet_sniffer_gui.py
   ```

## Usage

1. Select the network interface you want to capture packets from.
2. Apply any desired filters (IP address, port number, content, or protocol).
3. Click "Start Sniffing" to begin capturing packets.
4. View captured packets and real-time protocol statistics in the GUI.
5. Save captured packets to a PCAP file or export summaries to CSV or JSON formats.
6. Stop sniffing when you're done.

## Contributing

Contributions are welcome! Please submit pull requests to help improve this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For any issues or suggestions, feel free to open an issue on GitHub or contact me at jordanryancalvert@gmail.com