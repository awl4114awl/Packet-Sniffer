import tkinter as tk
from tkinter import scrolledtext, filedialog, Toplevel, messagebox, Checkbutton, BooleanVar, OptionMenu, StringVar
from threading import Thread, Event
from scapy.all import sniff, wrpcap
import psutil
import csv
import json
import logging
import os

class PacketSnifferApp(tk.Tk):
    def __init__(self):
        super().__init__()

        # Set up logging
        self.setup_logging()

        # Set up dark mode theme (default)
        self.bg_color = "#2e2e2e"
        self.fg_color = "#ffffff"
        self.button_color = "#444444"
        self.button_text_color = "#ffffff"
        self.highlight_color = "#444444"
        self.alt_bg_color = "#3b3b3b"  # Alternate background color

        self.configure(bg=self.bg_color)
        self.title("Packet Sniffer")
        self.geometry("600x700")
        self.minsize(600, 700)
        self.maxsize(600, 700)

        # Create a text area for displaying packets
        self.text_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=70, height=15,
                                                   bg=self.bg_color, fg=self.fg_color, insertbackground=self.fg_color)
        self.text_area.pack(pady=10)
        self.text_area.bind("<Double-1>", self.show_packet_details)  # Bind double-click event
        self.text_area.tag_configure("highlight", background=self.highlight_color)
        self.text_area.tag_configure("odd", background=self.bg_color)
        self.text_area.tag_configure("even", background=self.alt_bg_color)

        # Network Interface Selection
        self.create_interface_selection()

        # Advanced Filters
        self.create_advanced_filters()

        # Protocol Selection
        self.create_protocol_selection()

        # Statistics display
        self.stats_frame = tk.Frame(self, bg=self.bg_color)
        self.stats_frame.pack(pady=10)

        self.packet_count_label = tk.Label(self.stats_frame, text="Packets Captured: 0", bg=self.bg_color, fg=self.fg_color)
        self.packet_count_label.pack()

        self.protocol_stats_label = tk.Label(self.stats_frame, text="Protocol Distribution: ", bg=self.bg_color, fg=self.fg_color)
        self.protocol_stats_label.pack()

        # Buttons frame
        button_frame = tk.Frame(self, bg=self.bg_color)
        button_frame.pack(pady=10, fill=tk.X)

        # Start and Stop buttons
        self.start_button = tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing,
                                      bg=self.button_color, fg=self.button_text_color)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=5, expand=True, fill='x')

        self.stop_button = tk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED,
                                     bg=self.button_color, fg=self.button_text_color)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=5, expand=True, fill='x')

        self.save_button = tk.Button(button_frame, text="Save PCAP", command=self.save_packets, state=tk.DISABLED,
                                     bg=self.button_color, fg=self.button_text_color)
        self.save_button.pack(side=tk.LEFT, padx=10, pady=5, expand=True, fill='x')

        self.export_csv_button = tk.Button(button_frame, text="Export to CSV", command=self.export_to_csv, state=tk.DISABLED,
                                           bg=self.button_color, fg=self.button_text_color)
        self.export_csv_button.pack(side=tk.LEFT, padx=10, pady=5, expand=True, fill='x')

        self.export_json_button = tk.Button(button_frame, text="Export to JSON", command=self.export_to_json, state=tk.DISABLED,
                                            bg=self.button_color, fg=self.button_text_color)
        self.export_json_button.pack(side=tk.LEFT, padx=10, pady=5, expand=True, fill='x')

        self.sniffing_thread = None
        self.stop_event = Event()
        self.captured_packets = []
        self.packet_count = 0
        self.protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.alert_threshold = 100
        self.buffer = []
        self.buffer_size = 50

    def setup_logging(self):
        log_file = "packet_sniffer.log"
        logging.basicConfig(filename=log_file, level=logging.DEBUG,
                            format="%(asctime)s - %(levelname)s - %(message)s")
        logging.info("Application started")

    def create_interface_selection(self):
        interface_frame = tk.Frame(self, bg=self.bg_color)
        interface_frame.pack(pady=5)

        tk.Label(interface_frame, text="Select Interface:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5, pady=2, sticky="e")

        # Retrieve interface names using psutil
        self.interfaces = {iface: addrs[0].address for iface, addrs in psutil.net_if_addrs().items() if addrs}
        self.selected_interface = StringVar(value=list(self.interfaces.keys())[0])

        interface_menu = OptionMenu(interface_frame, self.selected_interface, *self.interfaces.keys())
        interface_menu.config(bg=self.button_color, fg=self.fg_color, activebackground=self.highlight_color)
        interface_menu.grid(row=0, column=1, padx=5, pady=2, sticky="w")

    def create_advanced_filters(self):
        filter_frame = tk.Frame(self, bg=self.bg_color)
        filter_frame.pack(pady=5)

        # IP Address Filter
        tk.Label(filter_frame, text="IP Address Filter:", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, padx=5, pady=2, sticky="e")
        self.ip_filter_entry = tk.Entry(filter_frame, width=20, bg=self.bg_color, fg=self.fg_color)
        self.ip_filter_entry.grid(row=0, column=1, padx=5, pady=2, sticky="w")

        # Port Number Filter
        tk.Label(filter_frame, text="Port Number Filter:", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, padx=5, pady=2, sticky="e")
        self.port_filter_entry = tk.Entry(filter_frame, width=20, bg=self.bg_color, fg=self.fg_color)
        self.port_filter_entry.grid(row=1, column=1, padx=5, pady=2, sticky="w")

        # Packet Content Filter
        tk.Label(filter_frame, text="Content Filter:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, padx=5, pady=2, sticky="e")
        self.content_filter_entry = tk.Entry(filter_frame, width=20, bg=self.bg_color, fg=self.fg_color)
        self.content_filter_entry.grid(row=2, column=1, padx=5, pady=2, sticky="w")

    def create_protocol_selection(self):
        protocol_frame = tk.Frame(self, bg=self.bg_color)
        protocol_frame.pack(pady=5)

        self.tcp_var = BooleanVar()
        self.udp_var = BooleanVar()
        self.icmp_var = BooleanVar()

        tcp_checkbox = Checkbutton(protocol_frame, text="TCP", variable=self.tcp_var, bg=self.bg_color, fg=self.fg_color,
                                   selectcolor=self.alt_bg_color, activebackground=self.bg_color)
        udp_checkbox = Checkbutton(protocol_frame, text="UDP", variable=self.udp_var, bg=self.bg_color, fg=self.fg_color,
                                   selectcolor=self.alt_bg_color, activebackground=self.bg_color)
        icmp_checkbox = Checkbutton(protocol_frame, text="ICMP", variable=self.icmp_var, bg=self.bg_color, fg=self.fg_color,
                                    selectcolor=self.alt_bg_color, activebackground=self.bg_color)

        tcp_checkbox.grid(row=0, column=0, padx=10)
        udp_checkbox.grid(row=0, column=1, padx=10)
        icmp_checkbox.grid(row=0, column=2, padx=10)

    def packet_callback(self, packet):
        if self.filter_packet(packet):
            self.buffer.append(packet)
            if len(self.buffer) >= self.buffer_size:
                self.process_buffer()

    def process_buffer(self):
        for packet in self.buffer:
            self.captured_packets.append(packet)
            self.packet_count += 1
            self.update_protocol_count(packet)
            self.update_stats_display()

            packet_summary = f"{self.packet_count}: {packet.summary()}"
            tag = "even" if self.packet_count % 2 == 0 else "odd"

            self.text_area.insert(tk.END, packet_summary + "\n", tag)
            self.text_area.insert(tk.END, "-"*70 + "\n", tag)  # Separator line
            self.text_area.yview(tk.END)

        self.buffer.clear()

        # Trigger alert if threshold is met
        if self.packet_count >= self.alert_threshold:
            self.trigger_alert()

    def filter_packet(self, packet):
        # Apply IP address filter
        ip_filter = self.ip_filter_entry.get().strip()
        if ip_filter and ip_filter not in str(packet):
            return False

        # Apply port number filter
        port_filter = self.port_filter_entry.get().strip()
        if port_filter and port_filter not in str(packet):
            return False

        # Apply content filter
        content_filter = self.content_filter_entry.get().strip()
        if content_filter and content_filter not in str(packet):
            return False

        # Apply protocol filter
        if self.tcp_var.get() and packet.haslayer("TCP"):
            return True
        if self.udp_var.get() and packet.haslayer("UDP"):
            return True
        if self.icmp_var.get() and packet.haslayer("ICMP"):
            return True

        # If no protocol filters are selected, accept all
        if not any([self.tcp_var.get(), self.udp_var.get(), self.icmp_var.get()]):
            return True

        return False

    def update_protocol_count(self, packet):
        if packet.haslayer("TCP"):
            self.protocol_count["TCP"] += 1
        elif packet.haslayer("UDP"):
            self.protocol_count["UDP"] += 1
        elif packet.haslayer("ICMP"):
            self.protocol_count["ICMP"] += 1
        else:
            self.protocol_count["Other"] += 1

    def update_stats_display(self):
        self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")
        self.protocol_stats_label.config(text=f"Protocol Distribution: TCP={self.protocol_count['TCP']} "
                                              f"UDP={self.protocol_count['UDP']} ICMP={self.protocol_count['ICMP']} "
                                              f"Other={self.protocol_count['Other']}")

    def start_sniffing(self):
        self.stop_event.clear()
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.export_csv_button.config(state=tk.DISABLED)
        self.export_json_button.config(state=tk.DISABLED)
        self.text_area.delete(1.0, tk.END)  # Clear the text area
        self.captured_packets = []  # Clear captured packets
        self.packet_count = 0  # Reset packet count
        self.protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}  # Reset protocol counts
        self.update_stats_display()  # Update stats display

        self.sniffing_thread = Thread(target=self.sniff_packets)
        self.sniffing_thread.start()

        logging.info("Packet sniffing started")

    def sniff_packets(self):
        try:
            sniff(iface=self.selected_interface.get(), prn=self.packet_callback, stop_filter=self.stop_sniffer)
        except Exception as e:
            logging.error(f"Error during packet sniffing: {e}")
            messagebox.showerror("Error", f"An error occurred during packet sniffing: {e}")

    def stop_sniffer(self, packet):
        return self.stop_event.is_set()

    def stop_sniffing(self):
        self.stop_event.set()
        if self.sniffing_thread is not None:
            self.sniffing_thread.join(timeout=1)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)
        self.export_csv_button.config(state=tk.NORMAL)
        self.export_json_button.config(state=tk.NORMAL)

        logging.info("Packet sniffing stopped")

    def save_packets(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                                 filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            try:
                wrpcap(file_path, self.captured_packets)
                messagebox.showinfo("Save Successful", f"Packets saved to {file_path}")
                logging.info(f"Packets saved to {file_path}")
            except Exception as e:
                logging.error(f"Error saving packets: {e}")
                messagebox.showerror("Error", f"Failed to save packets: {e}")

    def export_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            try:
                with open(file_path, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Packet Number", "Summary"])
                    for i, packet in enumerate(self.captured_packets, 1):
                        writer.writerow([i, packet.summary()])
                messagebox.showinfo("Export Successful", f"Packets exported to {file_path}")
                logging.info(f"Packets exported to CSV at {file_path}")
            except Exception as e:
                logging.error(f"Error exporting packets to CSV: {e}")
                messagebox.showerror("Error", f"Failed to export packets to CSV: {e}")

    def export_to_json(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                 filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            try:
                packet_summaries = [{"Packet Number": i+1, "Summary": packet.summary()}
                                    for i, packet in enumerate(self.captured_packets)]
                with open(file_path, 'w') as file:
                    json.dump(packet_summaries, file, indent=4)
                messagebox.showinfo("Export Successful", f"Packets exported to {file_path}")
                logging.info(f"Packets exported to JSON at {file_path}")
            except Exception as e:
                logging.error(f"Error exporting packets to JSON: {e}")
                messagebox.showerror("Error", f"Failed to export packets to JSON: {e}")

    def show_packet_details(self, event):
        try:
            # Clear previous highlights
            self.text_area.tag_remove("highlight", "1.0", tk.END)

            # Get the line number
            packet_index = (int(index) + 1) // 2 - 1  # Adjust for the separator lines
            packet = self.captured_packets[packet_index]

            # Highlight the selected line
            line_start = f"{index}.0"
            line_end = f"{index}.end"
            self.text_area.tag_add("highlight", line_start, line_end)

            # Create a new window to show packet details
            details_window = Toplevel(self)
            details_window.title("Packet Details")
            details_window.geometry("400x300")

            packet_details_text.pack(padx=10, pady=10)

            packet_details = packet.show(dump=True)
            packet_details_text.insert(tk.END, packet_details)
            packet_details_text.config(state=tk.DISABLED)

        except Exception as e:
            logging.error(f"Error displaying packet details: {e}")
            messagebox.showerror("Error", f"Failed to show packet details: {e}")

    def trigger_alert(self):
        self.bell()  # Play a sound
        messagebox.showwarning("Alert", f"Packet count has reached {self.alert_threshold}.")
        logging.warning(f"Packet count threshold reached: {self.packet_count}")

if __name__ == "__main__":
    app = PacketSnifferApp()
    app.mainloop()
