import sys
import os
import pefile
import hashlib
import pyWinhook
import pythoncom
import win32api
import win32file
import win32con
import winreg
from scapy.all import *
import volatility3
from volatility3.cli import text_renderer
from volatility3.framework import contexts, automagic
from volatility3.plugins.windows import pslist
from threading import Thread

def analyze_pe(file_path, result_file):
    pe = pefile.PE(file_path)
    
    with open(result_file, 'a') as f:
        f.write("\n--- PE File Analysis ---\n")
        f.write(f"File: {file_path}\n")
    
        f.write("\nSections:\n")
        for section in pe.sections:
            f.write(f"{section.Name.decode().rstrip(chr(0))}: "
                    f"VA: {hex(section.VirtualAddress)}, "
                    f"Size: {hex(section.Misc_VirtualSize)}, "
                    f"Raw Size: {section.SizeOfRawData}\n")
    
        f.write("\nImported DLLs and functions:\n")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            f.write(f"{entry.dll.decode()}\n")
            for func in entry.imports:
                f.write(f"\t{func.name.decode() if func.name else 'ordinal-' + str(func.ordinal)}\n")
    
        f.write("\nExported functions:\n")
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                f.write(f"{exp.name.decode() if exp.name else ''}: {hex(exp.address)}\n")

def extract_strings(file_path, result_file, min_length=4):
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
    
    with open(result_file, 'a') as f:
        f.write("\n--- Extracted Strings ---\n")
        for s in strings:
            f.write(f"{s}\n")

def get_file_info(file_path, result_file):
    with open(result_file, 'w') as f:
        f.write("\n--- File Information ---\n")
        f.write(f"File Name: {os.path.basename(file_path)}\n")
        f.write(f"File Size: {os.path.getsize(file_path)} bytes\n")
    
        with open(file_path, 'rb') as f_content:
            content = f_content.read()
            f.write(f"MD5: {hashlib.md5(content).hexdigest()}\n")
            f.write(f"SHA1: {hashlib.sha1(content).hexdigest()}\n")
            f.write(f"SHA256: {hashlib.sha256(content).hexdigest()}\n")

def monitor_file_system(result_file):
    def on_file_change(event):
        with open(result_file, 'a') as f:
            f.write(f"File system change detected: {event.FileName}\n")
            f.flush()

    path_to_watch = os.path.dirname(result_file)
    hDir = win32file.CreateFile(
        path_to_watch,
        win32con.FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
        None
    )

    while True:
        try:
            results = win32file.ReadDirectoryChangesW(
                hDir,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_SIZE |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY,
                None,
                None
            )
            for result in results:
                on_file_change(result)
        except Exception as e:
            with open(result_file, 'a') as f:
                f.write(f"File system monitoring error: {e}\n")

def monitor_registry(result_file):
    def on_registry_change(event):
        with open(result_file, 'a') as f:
            f.write(f"Registry change detected: {event.Key}\n")
            f.flush()

    def watch_registry():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software", 0, winreg.KEY_NOTIFY)
            while True:
                try:
                    winreg.NotifyChangeKeyValue(key, True, winreg.REG_NOTIFY_CHANGE_LAST_SET, None, None)
                    on_registry_change({'Key': 'Software'})
                except Exception as e:
                    with open(result_file, 'a') as f:
                        f.write(f"Registry monitoring error: {e}\n")
        except Exception as e:
            with open(result_file, 'a') as f:
                f.write(f"Registry access error: {e}\n")

    registry_thread = Thread(target=watch_registry)
    registry_thread.start()

def setup_hooks(file_path):
    dynamic_log_path = file_path.rsplit('.', 1)[0] + '_dynamic.txt'
    
    with open(dynamic_log_path, 'w') as log_file:
        def on_keyboard_event(event):
            log_file.write(f'Key: {event.Key}\n')
            log_file.flush()  # 즉시 파일에 기록
            return True

        # Key and Mouse Hooks
        hm = pyWinhook.HookManager()
        hm.KeyDown = on_keyboard_event
        hm.HookKeyboard()
        
        print(f"Dynamic analysis started. Results are being saved to: {dynamic_log_path}")
        print("Press Ctrl+C to stop.")

        try:
            while True:
                pythoncom.PumpWaitingMessages()
                time.sleep(1)  # CPU 사용을 줄이기 위한 대기
        except KeyboardInterrupt:
            print("\nDynamic analysis stopped.")

def capture_network(file_path):
    network_log_path = file_path.rsplit('.', 1)[0] + '_network.txt'

    def packet_callback(packet):
        with open(network_log_path, 'a') as f:
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                f.write(f"IP {ip_src} -> {ip_dst}\n")
                if packet.haslayer(TCP):
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    f.write(f"TCP {ip_src}:{sport} -> {ip_dst}:{dport}\n")
    
    print("\n--- Starting network capture. Press Ctrl+C to stop. ---")
    sniff(prn=packet_callback, store=0)

def analyze_memory_dump(dump_path, result_file):
    with open(result_file, 'a') as f:
        f.write("\n--- Memory Dump Analysis ---\n")
        context = contexts.Context()
        context.config['automagic.LayerStacker.single_location'] = dump_path
        automagics = automagic.available(context)
        
        plugin = pslist.PsList(context, config_path='', progress_callback=lambda x, y: None)
        tree = plugin.run()
        text_renderer.TreeGrid(
            [("PID", int), ("PPID", int), ("ImageFileName", str), ("Offset", int), ("Threads", int), ("Handles", int),
             ("SessionId", int), ("Wow64", bool), ("CreateTime", str), ("ExitTime", str)], tree).render(
            text_renderer.QuickTextRenderer())

def main(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return
    
    result_file = file_path.rsplit('.', 1)[0] + '_result.txt'
    get_file_info(file_path, result_file)
    
    print("Progress: 0%")
    try:
        analyze_pe(file_path, result_file)
    except pefile.PEFormatError:
        with open(result_file, 'a') as f:
            f.write("Error: Not a valid PE file.\n")
    
    print("Progress: 20%")
    extract_strings(file_path, result_file)
    
    print("Progress: 80%")
    
    print("Progress: 100%")
    print(f"Analysis complete. Results saved to {result_file}")

    print("\nChoose additional analysis options:")
    print("1. Set up hooks for dynamic analysis")
    print("2. Capture network traffic")
    print("3. Analyze memory dump")
    print("4. Exit")

    choice = input("Enter your choice (1-4): ")

    if choice == '1':
        setup_hooks(file_path)
    elif choice == '2':
        capture_network(file_path)
    elif choice == '3':
        dump_path = input("Enter the path to the memory dump file: ")
        analyze_memory_dump(dump_path, result_file)
    elif choice == '4':
        print("Exiting...")
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_exe>")
    else:
        main(sys.argv[1])
