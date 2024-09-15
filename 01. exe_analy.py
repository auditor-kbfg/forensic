import sys
import os
import pefile
import hashlib
import pyWinhook
import pythoncom
from scapy.all import *
import volatility3
from volatility3.cli import text_renderer
from volatility3.framework import contexts, automagic
from volatility3.plugins.windows import pslist

def analyze_pe(file_path):
    pe = pefile.PE(file_path)
    
    print("\n--- PE File Analysis ---")
    print(f"File: {file_path}")
    
    print("\nSections:")
    for section in pe.sections:
        print(f"{section.Name.decode().rstrip('\x00')}: "
              f"VA: {hex(section.VirtualAddress)}, "
              f"Size: {hex(section.Misc_VirtualSize)}, "
              f"Raw Size: {section.SizeOfRawData}")
    
    print("\nImported DLLs and functions:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll.decode())
        for func in entry.imports:
            print(f"\t{func.name.decode() if func.name else 'ordinal-' + str(func.ordinal)}")
    
    print("\nExported functions:")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"{exp.name.decode() if exp.name else ''}: {hex(exp.address)}")

def extract_strings(file_path, min_length=4):
    with open(file_path, 'rb') as f:
        content = f.read()
    
    strings = []
    current_string = b''
    for byte in content:
        if 32 <= byte <= 126:  # printable ASCII characters
            current_string += bytes([byte])
        elif len(current_string) >= min_length:
            strings.append(current_string.decode('ascii', errors='ignore'))
            current_string = b''
        else:
            current_string = b''
    
    print("\n--- Extracted Strings ---")
    for s in strings:
        print(s)

def get_file_info(file_path):
    print("\n--- File Information ---")
    print(f"File Name: {os.path.basename(file_path)}")
    print(f"File Size: {os.path.getsize(file_path)} bytes")
    
    with open(file_path, 'rb') as f:
        content = f.read()
        print(f"MD5: {hashlib.md5(content).hexdigest()}")
        print(f"SHA1: {hashlib.sha1(content).hexdigest()}")
        print(f"SHA256: {hashlib.sha256(content).hexdigest()}")

def setup_hooks():
    def on_keyboard_event(event):
        print(f'Key: {event.Key}')
        return True

    def on_mouse_event(event):
        print(f'Mouse position: ({event.Position[0]}, {event.Position[1]})')
        return True

    hm = pyWinhook.HookManager()
    hm.KeyDown = on_keyboard_event
    hm.MouseAll = on_mouse_event
    hm.HookKeyboard()
    hm.HookMouse()
    print("\n--- Hooks set up. Press Ctrl+C to stop. ---")
    pythoncom.PumpMessages()

def capture_network():
    def packet_callback(packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(f"IP {ip_src} -> {ip_dst}")
            if packet.haslayer(TCP):
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                print(f"TCP {ip_src}:{sport} -> {ip_dst}:{dport}")

    print("\n--- Starting network capture. Press Ctrl+C to stop. ---")
    sniff(prn=packet_callback, store=0)

def analyze_memory_dump(dump_path):
    print("\n--- Memory Dump Analysis ---")
    context = contexts.Context()
    context.config['automagic.LayerStacker.single_location'] = dump_path
    automagics = automagic.available(context)
    
    plugin = pslist.PsList(context, config_path='', progress_callback=lambda x, y: None)
    tree = plugin.run()
    text_renderer.TreeGrid([("PID", int), ("PPID", int), ("ImageFileName", str), ("Offset", int), ("Threads", int), ("Handles", int), ("SessionId", int), ("Wow64", bool), ("CreateTime", str), ("ExitTime", str)], tree).render(text_renderer.QuickTextRenderer())

def main(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return

    get_file_info(file_path)
    
    try:
        analyze_pe(file_path)
    except pefile.PEFormatError:
        print("Error: Not a valid PE file.")
    
    extract_strings(file_path)

    print("\nChoose additional analysis options:")
    print("1. Set up hooks for dynamic analysis")
    print("2. Capture network traffic")
    print("3. Analyze memory dump")
    print("4. Exit")

    choice = input("Enter your choice (1-4): ")

    if choice == '1':
        setup_hooks()
    elif choice == '2':
        capture_network()
    elif choice == '3':
        dump_path = input("Enter the path to the memory dump file: ")
        analyze_memory_dump(dump_path)
    elif choice == '4':
        print("Exiting...")
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_exe>")
    else:
        main(sys.argv[1])
