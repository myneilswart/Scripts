## A Python Packet Capturer

import os
import sys
import signal
import winreg
from io import StringIO
from datetime import datetime
from scapy.all import sniff, wrpcap, hexdump

captured_packets = []
mode = "1"
capture_finished = False

def get_desktop():
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
    desktop = winreg.QueryValueEx(key, "Desktop")[0]
    return desktop

def packet_to_text(packet, mode):
    output = StringIO()
    output.write("\n=== New Packet ===\n")

    if mode == "1":
        output.write(packet.summary() + "\n")

    elif mode == "2":
        output.write(packet.summary() + "\n")
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        packet.show()
        show_output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        output.write(show_output)

    elif mode == "3":
        if packet.haslayer("Raw"):
            raw_data = packet["Raw"].load
            output.write("--- Raw Payload (Hexdump) ---\n")
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            hexdump(raw_data)
            hex_output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            output.write(hex_output)
            try:
                text = raw_data.decode("utf-8")
                output.write("\n--- Raw Payload (UTF-8 Text) ---\n")
                output.write(text + "\n")
            except UnicodeDecodeError:
                output.write("\n--- Raw Payload (Not UTF-8 Printable) ---\n")

    elif mode == "4":
        output.write(packet.summary() + "\n")
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        packet.show()
        show_output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        output.write(show_output)
        if packet.haslayer("Raw"):
            raw_data = packet["Raw"].load
            output.write("\n--- Raw Payload (Hexdump) ---\n")
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            hexdump(raw_data)
            hex_output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            output.write(hex_output)
            try:
                text = raw_data.decode("utf-8")
                output.write("\n--- Raw Payload (UTF-8 Text) ---\n")
                output.write(text + "\n")
            except UnicodeDecodeError:
                output.write("\n--- Raw Payload (Not UTF-8 Printable) ---\n")

    return output.getvalue()

def process_packet(packet):
    captured_packets.append(packet)
    text = packet_to_text(packet, mode)
    print(text)

def save_txt_to_desktop():
    txt_filename = input("Enter filename (default: capture.txt): ").strip()
    if not txt_filename:
        txt_filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    elif not txt_filename.endswith(".txt"):
        txt_filename += ".txt"
    filename = os.path.join(get_desktop(), txt_filename)
    with open(filename, "w") as f:
        f.write(f"Packet Capture — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total packets: {len(captured_packets)}\n")
        f.write("=" * 50 + "\n")
        for i, pkt in enumerate(captured_packets, 1):
            f.write(f"\n--- Packet {i} ---")
            f.write(packet_to_text(pkt, mode))
    print(f"\n✅ Your capture has been saved as a .txt file to your Desktop:")
    print(f"   {filename}")

def save_pcap_to_desktop():
    pcap_filename = input("Enter filename (default: capture.pcap): ").strip()
    if not pcap_filename:
        pcap_filename = "capture.pcap"
    elif not pcap_filename.endswith(".pcap"):
        pcap_filename += ".pcap"
    pcap_path = os.path.join(get_desktop(), pcap_filename)
    wrpcap(pcap_path, captured_packets)
    print(f"\n✅ Your capture has been saved as a .pcap file to your Desktop:")
    print(f"   {pcap_path}")

def print_to_screen():
    print("\nHere are the captured packets:\n")
    for i, pkt in enumerate(captured_packets, 1):
        print(f"\n--- Packet {i} ---")
        print(packet_to_text(pkt, mode))
    input("\nPress Enter to close...")

def finish_capture():
    global capture_finished
    if capture_finished:
        return
    capture_finished = True

    if not captured_packets:
        print("\nNo packets captured.")
        return

    print("\nHow would you like to save the capture?")
    print("1 = Save as .txt (readable in Notepad)")
    print("2 = Save as .pcap (for Wireshark)")
    print("3 = Print to screen only")
    print("4 = All of the above")
    save_choice = input("Enter choice (1/2/3/4): ").strip()

    if save_choice == "1":
        save_txt_to_desktop()

    elif save_choice == "2":
        save_pcap_to_desktop()

    elif save_choice == "3":
        print_to_screen()

    elif save_choice == "4":
        save_txt_to_desktop()
        save_pcap_to_desktop()
        print_to_screen()

    else:
        print("Invalid choice, printing to screen only.")
        print_to_screen()

    print("\nCapture finished. Goodbye!")

def handle_ctrl_c(sig, frame):
    print("\n\nCtrl+C detected — stopping capture...")
    finish_capture()
    sys.exit(0)

def main():
    global mode

    signal.signal(signal.SIGINT, handle_ctrl_c)

    print("Welcome to Python Packet Sniffer!\n")

    print("Choose output verbosity:")
    print("1 = Summaries only")
    print("2 = Full packet details")
    print("3 = Payloads only")
    print("4 = Everything")
    mode = input("Enter choice (1/2/3/4): ").strip()
    if mode not in ["1", "2", "3", "4"]:
        print("Invalid choice, defaulting to summaries only.")
        mode = "1"

    use_filter = input("\nDo you want to apply a filter? (y/n): ").strip().lower()
    packet_filter = ""
    if use_filter == "y":
        packet_filter = input("Enter your filter (e.g. 'tcp', 'udp', 'tcp port 80'): ").strip()

    count_input = input("\nHow many packets to capture? (0 = unlimited): ").strip()
    try:
        packet_count = int(count_input)
    except ValueError:
        packet_count = 0

    print("\nStarting capture...")
    print("👉 Press Ctrl+C to stop at any time.\n")

    try:
        sniff(
            filter=packet_filter if packet_filter else None,
            prn=process_packet,
            count=packet_count if packet_count > 0 else 0
        )
    except KeyboardInterrupt:
        pass

    finish_capture()

if __name__ == "__main__":
    main()
