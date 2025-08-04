import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import subprocess
import os
import re
import threading
from pathlib import Path
import time
import shutil

class OculusFileTransferGUI:
    def __init__(self, root):
        # ... (previous init code up to actions_frame) ...
        self.root = root
        self.root.title("Oculus Quest File Transfer")
        self.root.geometry("1000x850") # Increased height slightly for new button

        self.discovered_quest_paths = {
            "Internal Storage": "/storage/emulated/0",
            "Downloads": "/storage/emulated/0/Download",
            "Pictures": "/storage/emulated/0/Pictures",
            "Movies": "/storage/emulated/0/Movies",
            "Android/obb": "/storage/emulated/0/Android/obb",
            "Android/data": "/storage/emulated/0/Android/data"
        }
        self.device_serial = None
        self.connected = False

        # <<< NEW STATE VARIABLES FOR MOVE >>>
        self.is_selecting_quest_move_destination = False
        self.quest_move_source_items_info = [] # To store {'name': str} of items to move
        self.quest_move_source_base_path = ""  # To store the original path of selected items
        # <<< END NEW STATE VARIABLES >>>


        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Connection frame (no changes)
        self.connection_frame = ttk.LabelFrame(self.main_frame, text="Connection", padding="5")
        self.connection_frame.grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky=(tk.W, tk.E))
        self.connection_mode_var = tk.StringVar(value="Wireless")
        self.wireless_radio = ttk.Radiobutton(self.connection_frame, text="Wireless", variable=self.connection_mode_var,
                                              value="Wireless", command=self.toggle_connection_mode_ui)
        self.wireless_radio.grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.usb_radio = ttk.Radiobutton(self.connection_frame, text="USB", variable=self.connection_mode_var,
                                         value="USB", command=self.toggle_connection_mode_ui)
        self.usb_radio.grid(row=1, column=0, padx=5, pady=2, sticky=tk.W)
        self.ip_label = ttk.Label(self.connection_frame, text="Quest IP:")
        self.ip_label.grid(row=0, column=1, padx=5, sticky=tk.E)
        self.ip_var = tk.StringVar()
        self.ip_entry = ttk.Entry(self.connection_frame, textvariable=self.ip_var)
        self.ip_entry.grid(row=0, column=2, padx=5)
        self.port_label = ttk.Label(self.connection_frame, text="Port:")
        self.port_label.grid(row=0, column=3, padx=5, sticky=tk.E)
        self.port_var = tk.StringVar(value="5555")
        self.port_entry = ttk.Entry(self.connection_frame, textvariable=self.port_var, width=8)
        self.port_entry.grid(row=0, column=4, padx=5)
        self.find_ip_btn = ttk.Button(self.connection_frame, text="Find Quest IP (via USB)", command=self.find_quest_ip)
        self.find_ip_btn.grid(row=0, column=5, padx=5)
        self.connect_btn = ttk.Button(self.connection_frame, text="Connect", command=self.connect_quest)
        self.connect_btn.grid(row=1, column=1, columnspan=2, padx=5, pady=5)
        self.status_var = tk.StringVar(value="Not Connected")
        self.status_label = ttk.Label(self.connection_frame, textvariable=self.status_var)
        self.status_label.grid(row=1, column=3, columnspan=3, padx=5, sticky=tk.W)

        # Local files frame (no changes)
        self.local_frame = ttk.LabelFrame(self.main_frame, text="Local Files", padding="5")
        self.local_frame.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.local_path_frame = ttk.Frame(self.local_frame)
        self.local_path_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E))
        self.local_path_var = tk.StringVar(value=str(Path.cwd()))
        self.local_path_entry = ttk.Entry(self.local_path_frame, textvariable=self.local_path_var)
        self.local_path_entry.grid(row=0, column=0, padx=5, sticky=(tk.W, tk.E))
        self.browse_btn = ttk.Button(self.local_path_frame, text="Browse", command=self.browse_local)
        self.browse_btn.grid(row=0, column=1, padx=5)
        drives = []
        if os.name == 'nt':
            drives = [f"{d}:\\" for d in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if os.path.exists(f"{d}:")]
            self.drive_var = tk.StringVar(value=drives[0] if drives else "")
            if drives:
                self.drive_menu = ttk.OptionMenu(self.local_path_frame, self.drive_var, drives[0], *drives,
                                               command=self.change_drive)
                self.drive_menu.grid(row=0, column=2, padx=5)
        self.local_up_btn = ttk.Button(self.local_path_frame, text="↑ Up", command=self.local_up)
        self.local_up_btn.grid(row=0, column=3 if os.name == 'nt' and drives else 2, padx=5)
        self.local_tree = ttk.Treeview(self.local_frame, selectmode='extended', columns=('size', 'type', 'checked'))
        self.local_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.local_tree.heading('#0', text='Name'); self.local_tree.heading('size', text='Size')
        self.local_tree.heading('type', text='Type'); self.local_tree.heading('checked', text='Select')
        self.local_tree.column('checked', width=50, anchor='center', stretch=tk.NO)
        self.local_tree.column('size', width=100, stretch=tk.NO); self.local_tree.column('type', width=70, stretch=tk.NO)
        self.local_scroll = ttk.Scrollbar(self.local_frame, orient=tk.VERTICAL, command=self.local_tree.yview)
        self.local_scroll.grid(row=1, column=1, sticky=(tk.N, tk.S)); self.local_tree.configure(yscrollcommand=self.local_scroll.set)

        # Quest files frame (no changes)
        self.quest_frame = ttk.LabelFrame(self.main_frame, text="Quest Files", padding="5")
        self.quest_frame.grid(row=1, column=1, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.quest_path_frame = ttk.Frame(self.quest_frame)
        self.quest_path_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E))
        self.quest_path_var = tk.StringVar(value="/storage/emulated/0")
        self.quest_path_entry = ttk.Entry(self.quest_path_frame, textvariable=self.quest_path_var)
        self.quest_path_entry.grid(row=0, column=0, padx=5, sticky=(tk.W, tk.E))
        self.quest_up_btn = ttk.Button(self.quest_path_frame, text="↑ Up", command=self.quest_up)
        self.quest_up_btn.grid(row=0, column=1, padx=5)
        self.current_quest_path_selection_var = tk.StringVar(value="Quick Access")
        self.quest_dynamic_paths_menu = ttk.OptionMenu(self.quest_path_frame, self.current_quest_path_selection_var,
            "Quick Access", command=self.change_quest_path_from_dropdown)
        self.quest_dynamic_paths_menu.grid(row=0, column=2, padx=5); self._rebuild_dynamic_paths_menu()
        self.scan_paths_btn = ttk.Button(self.quest_path_frame, text="Scan Device Paths", command=self.scan_quest_paths)
        self.scan_paths_btn.grid(row=0, column=3, padx=5)
        self.quest_tree = ttk.Treeview(self.quest_frame, selectmode='extended', columns=('size', 'type', 'checked'))
        self.quest_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.quest_tree.heading('#0', text='Name'); self.quest_tree.heading('size', text='Size')
        self.quest_tree.heading('type', text='Type'); self.quest_tree.heading('checked', text='Select')
        self.quest_tree.column('checked', width=50, anchor='center', stretch=tk.NO)
        self.quest_tree.column('size', width=100, stretch=tk.NO); self.quest_tree.column('type', width=70, stretch=tk.NO)
        self.quest_scroll = ttk.Scrollbar(self.quest_frame, orient=tk.VERTICAL, command=self.quest_tree.yview)
        self.quest_scroll.grid(row=1, column=1, sticky=(tk.N, tk.S)); self.quest_tree.configure(yscrollcommand=self.quest_scroll.set)

        # Transfer buttons (no changes)
        self.transfer_frame = ttk.Frame(self.main_frame)
        self.transfer_frame.grid(row=2, column=0, columnspan=2, pady=5)
        self.to_quest_frame = ttk.LabelFrame(self.transfer_frame, text="Transfer to Quest →")
        self.to_quest_frame.grid(row=0, column=0, padx=5)
        self.transfer_selected_to_quest_btn = ttk.Button(self.to_quest_frame, text="Transfer Selected", command=lambda: self.transfer_files(to_quest=True, selected_only=True))
        self.transfer_selected_to_quest_btn.grid(row=0, column=0, padx=5, pady=2, sticky=tk.EW)
        self.transfer_folder_to_quest_btn = ttk.Button(self.to_quest_frame, text="Transfer Current Folder", command=lambda: self.transfer_files(to_quest=True, selected_only=False))
        self.transfer_folder_to_quest_btn.grid(row=1, column=0, padx=5, pady=2, sticky=tk.EW)
        self.from_quest_frame = ttk.LabelFrame(self.transfer_frame, text="← Transfer from Quest")
        self.from_quest_frame.grid(row=0, column=1, padx=5)
        self.transfer_selected_from_quest_btn = ttk.Button(self.from_quest_frame, text="Transfer Selected", command=lambda: self.transfer_files(to_quest=False, selected_only=True))
        self.transfer_selected_from_quest_btn.grid(row=0, column=0, padx=5, pady=2, sticky=tk.EW)
        self.transfer_folder_from_quest_btn = ttk.Button(self.from_quest_frame, text="Transfer Current Folder", command=lambda: self.transfer_files(to_quest=False, selected_only=False))
        self.transfer_folder_from_quest_btn.grid(row=1, column=0, padx=5, pady=2, sticky=tk.EW)


        self.actions_frame = ttk.Frame(self.main_frame)
        self.actions_frame.grid(row=3, column=0, columnspan=2, pady=5)

        self.local_actions_frame = ttk.LabelFrame(self.actions_frame, text="Local Actions")
        self.local_actions_frame.grid(row=0, column=0, padx=5, sticky=tk.N)
        self.delete_local_btn = ttk.Button(self.local_actions_frame, text="Delete Selected",
                                           command=lambda: self.delete_files(on_quest=False))
        self.delete_local_btn.grid(row=0, column=0, padx=5, pady=2, sticky=tk.EW)

        self.quest_actions_frame = ttk.LabelFrame(self.actions_frame, text="Quest Actions")
        self.quest_actions_frame.grid(row=0, column=1, padx=5, sticky=tk.N)
        self.delete_quest_btn = ttk.Button(self.quest_actions_frame, text="Delete Selected",
                                           command=lambda: self.delete_files(on_quest=True))
        self.delete_quest_btn.grid(row=0, column=0, padx=5, pady=2, sticky=tk.EW)

        # <<< MODIFIED >>> Move Quest Button
        self.move_quest_btn = ttk.Button(self.quest_actions_frame, text="Move Selected (Quest)",
                                         command=self.handle_move_quest_button_click) # Changed command
        self.move_quest_btn.grid(row=1, column=0, padx=5, pady=2, sticky=tk.EW)

        # <<< NEW >>> Set Destination Button (initially hidden or disabled)
        self.set_destination_quest_btn = ttk.Button(self.quest_actions_frame,
                                                    text="Set Current as Move Destination",
                                                    command=self.set_quest_move_destination)
        # self.set_destination_quest_btn.grid(row=2, column=0, padx=5, pady=2, sticky=tk.EW) # Will be gridded dynamically
        # <<< END NEW >>>

        # Configure grid weights
        self.root.columnconfigure(0, weight=1); self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1); self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(1, weight=1)
        self.local_frame.columnconfigure(0, weight=1); self.local_frame.rowconfigure(1, weight=1)
        self.quest_frame.columnconfigure(0, weight=1); self.quest_frame.rowconfigure(1, weight=1)
        self.local_path_frame.columnconfigure(0, weight=1); self.quest_path_frame.columnconfigure(0, weight=1)
        self.to_quest_frame.columnconfigure(0, weight=1); self.from_quest_frame.columnconfigure(0, weight=1)
        self.local_actions_frame.columnconfigure(0, weight=1); self.quest_actions_frame.columnconfigure(0, weight=1)
        self.actions_frame.columnconfigure(0, weight=1); self.actions_frame.columnconfigure(1, weight=1)


        self.local_tree.bind('<Double-Button-1>', self.local_tree_double_click)
        self.quest_tree.bind('<Double-Button-1>', self.quest_tree_double_click)
        self.local_path_entry.bind('<Return>', lambda e: self.refresh_local_files())
        self.quest_path_entry.bind('<Return>', lambda e: self.refresh_quest_files())
        self.local_tree.bind('<ButtonRelease-1>', self.toggle_checkbox)
        self.quest_tree.bind('<ButtonRelease-1>', self.toggle_checkbox)

        self.toggle_connection_mode_ui()
        self.refresh_local_files()
        self._update_quest_move_ui_state() # Initial UI state for move buttons


    def _get_adb_prefix(self): # ... (no changes)
        if self.device_serial:
            return ['adb', '-s', self.device_serial]
        return ['adb']

    def _run_adb_command(self, command_args, use_prefix=True, check=False, capture_output=True, text=True, timeout=None): # ... (no changes)
        prefix = self._get_adb_prefix() if use_prefix else ['adb']
        full_command = prefix + command_args
        try:
            return subprocess.run(full_command, capture_output=capture_output, text=text, check=check, timeout=timeout, startupinfo=self._get_startup_info())
        except FileNotFoundError:
            raise FileNotFoundError("ADB command not found. Ensure Android Platform Tools are installed and in your system's PATH.")

    def _get_startup_info(self): # ... (no changes)
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            return startupinfo
        return None

    def toggle_connection_mode_ui(self, *args): # ... (no changes)
        mode = self.connection_mode_var.get()
        if mode == "Wireless":
            self.ip_entry.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.NORMAL)
            self.find_ip_btn.config(state=tk.NORMAL)
        elif mode == "USB":
            self.ip_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.find_ip_btn.config(state=tk.DISABLED)

    def _rebuild_dynamic_paths_menu(self): # ... (no changes)
        menu = self.quest_dynamic_paths_menu["menu"]
        menu.delete(0, "end")
        menu.add_command(label="Quick Access",
                       command=lambda: self.current_quest_path_selection_var.set("Quick Access"))
        for display_name in sorted(self.discovered_quest_paths.keys()):
            menu.add_command(label=display_name,
                           command=lambda name=display_name: self.change_quest_path_from_dropdown(name))
        self.current_quest_path_selection_var.set("Quick Access")

    def change_quest_path_from_dropdown(self, selected_display_name): # ... (no changes)
        if selected_display_name == "Quick Access": return
        if selected_display_name in self.discovered_quest_paths:
            actual_path = self.discovered_quest_paths[selected_display_name]
            self.quest_path_var.set(actual_path)
            self.refresh_quest_files()
        else:
            messagebox.showwarning("Path Error", f"Path for '{selected_display_name}' not found.")

    def scan_quest_paths(self): # ... (no changes)
        if not self.connected:
            messagebox.showerror("Error", "Please connect to Quest first")
            return
        try:
            result = self._run_adb_command(['shell', 'ls -d /storage/*'])
            if result.returncode != 0:
                raise Exception(f"Failed to list /storage/*: {result.stderr}")
            storage_paths = result.stdout.strip().split('\n')
            accessible_paths_set = set(self.discovered_quest_paths.values())

            for path_group in [storage_paths, ['/sdcard', '/storage/self/primary']]:
                for path in path_group:
                    if not path: continue
                    path = path.strip() # Ensure no trailing spaces from ls
                    test_cmd_str = f'if [ -d "{path}" ] && [ -r "{path}" ] && [ -x "{path}" ]; then ls "{path}" > /dev/null 2>&1; if [ $? -eq 0 ]; then echo "ACCESSIBLE"; fi; fi'
                    test_result = self._run_adb_command(['shell', test_cmd_str])
                    if test_result.returncode == 0 and "ACCESSIBLE" in test_result.stdout:
                        accessible_paths_set.add(path)
            
            self.discovered_quest_paths.clear()
            for path in sorted(list(accessible_paths_set)):
                display_name = os.path.basename(path) if os.path.basename(path) else path
                original_display_name = display_name
                counter = 1
                while display_name in self.discovered_quest_paths and self.discovered_quest_paths[display_name] != path :
                    display_name = f"{original_display_name} ({counter})"
                    counter += 1
                if display_name not in self.discovered_quest_paths or self.discovered_quest_paths[display_name] == path:
                     self.discovered_quest_paths[display_name] = path
            
            self._rebuild_dynamic_paths_menu()
            messagebox.showinfo("Paths Scanned", "Accessible paths updated. Check 'Quick Access'.")
        except Exception as e:
            messagebox.showerror("Error Scanning Paths", f"Failed to scan paths: {str(e)}")

    def find_quest_ip(self): # ... (no changes)
        try:
            self.status_var.set("Finding IP: Checking USB..."); self.root.update_idletasks()
            self._run_adb_command(['version'], use_prefix=False, check=True)
            result = self._run_adb_command(['devices'], use_prefix=False)
            usb_device_serial = next((line.split('\t')[0] for line in result.stdout.strip().split('\n')
                                      if '\tdevice' in line and not re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', line)), None)
            if not usb_device_serial:
                messagebox.showinfo("Connect Device", "Please connect Quest via USB, enable USB debugging, then click OK.")
                raise Exception("No USB device found or device unauthorized.")

            temp_adb_prefix = ['adb', '-s', usb_device_serial]
            get_prop_cmd = temp_adb_prefix + ['shell', 'getprop', 'service.adb.tcp.port']
            current_port = subprocess.run(get_prop_cmd, capture_output=True, text=True, startupinfo=self._get_startup_info()).stdout.strip()

            if not current_port or current_port in ['0', '-1']:
                self.status_var.set("Finding IP: Enabling wireless ADB..."); self.root.update_idletasks()
                subprocess.run(temp_adb_prefix + ['tcpip', '5555'], check=True, capture_output=True, startupinfo=self._get_startup_info())
                time.sleep(1); current_port = '5555'
            
            self.status_var.set("Finding IP: Getting IP address..."); self.root.update_idletasks()
            result = subprocess.run(temp_adb_prefix + ['shell', 'ip', 'addr', 'show', 'wlan0'], capture_output=True, text=True, startupinfo=self._get_startup_info())
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if not ip_match: raise Exception("Could not find Quest IP address. Is WiFi enabled and connected?")
            
            ip_address = ip_match.group(1)
            self.ip_var.set(ip_address); self.port_var.set(current_port)
            self.status_var.set("IP Found. Enter in Wireless mode and Connect.")
            messagebox.showinfo("IP Found", f"Quest IP: {ip_address}\nPort: {current_port}\nDisconnect USB if connecting wirelessly.")
        except Exception as e:
            messagebox.showerror("Error Finding IP", str(e)); self.status_var.set("IP Find Failed")
    
    def connect_quest(self): # ... (no changes to logic, but added UI reset for move state)
        self.connected = False; self.device_serial = None
        self.status_var.set("Connecting..."); self.root.update_idletasks()
        mode = self.connection_mode_var.get()

        # <<< MODIFIED >>> Reset move state on connection attempt
        self._cancel_quest_move_destination_select_mode()

        def connect_task():
            try:
                if mode == "Wireless":
                    ip, port_str = self.ip_var.get(), self.port_var.get()
                    if not ip or not port_str: raise ValueError("IP and Port required for Wireless.")
                    port = int(port_str)
                    if not (1 <= port <= 65535): raise ValueError("Invalid port (1-65535).")
                    target_device = f'{ip}:{port}'
                    try: self._run_adb_command(['disconnect', target_device], use_prefix=False, timeout=5)
                    except Exception: pass 
                    result = self._run_adb_command(['connect', target_device], use_prefix=False, check=True, timeout=10)
                    if 'connected to' not in result.stdout.lower() and 'already connected' not in result.stdout.lower():
                         devices_res = self._run_adb_command(['devices'], use_prefix=False)
                         if target_device not in devices_res.stdout:
                            raise Exception(f"Connection failed to {target_device}: {result.stdout or result.stderr}")
                    self.device_serial = target_device
                elif mode == "USB":
                    result = self._run_adb_command(['devices'], use_prefix=False)
                    usb_devices = [line.split('\t')[0] for line in result.stdout.strip().split('\n')
                                   if '\tdevice' in line and not re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', line)]
                    if not usb_devices: raise Exception("No USB device found. Check connection & authorization.")
                    self.device_serial = usb_devices[0]
                
                self.connected = True
                self.status_var.set(f"Connected to {self.device_serial} ({mode})")
                self.refresh_quest_files()
                self.scan_quest_paths()
            except Exception as e:
                self.connected = False; self.device_serial = None
                messagebox.showerror("Connection Error", str(e))
                self.status_var.set("Connection Failed")
            finally: # <<< MODIFIED >>> Update UI state regardless of connection success/failure
                self.root.after(0, self._update_quest_move_ui_state)

        threading.Thread(target=connect_task, daemon=True).start()

    def browse_local(self): # ... (no changes)
        path = filedialog.askdirectory(initialdir=self.local_path_var.get())
        if path: self.local_path_var.set(path); self.refresh_local_files()
    
    def change_drive(self, drive): # ... (no changes)
        self.local_path_var.set(drive); self.refresh_local_files()
    
    def local_up(self): # ... (no changes)
        current_path = Path(self.local_path_var.get())
        if current_path.parent != current_path:
            self.local_path_var.set(str(current_path.parent)); self.refresh_local_files()

    def quest_up(self): # ... (no changes)
        if not self.connected: return
        # <<< MODIFIED >>> Ensure we are not in move destination selection mode when navigating
        if self.is_selecting_quest_move_destination:
             self.status_var.set("Navigating to Quest move destination... Use 'Set Current' or 'Cancel'.")
        current_path = self.quest_path_var.get().rstrip('/')
        if current_path and current_path != '/' and os.path.dirname(current_path) != current_path :
            new_path = os.path.dirname(current_path)
            if not new_path: new_path = '/' 
            self.quest_path_var.set(new_path); self.refresh_quest_files()

    def local_tree_double_click(self, event): # ... (no changes)
        item_id = self.local_tree.focus()
        if not item_id: return
        item_text = self.local_tree.item(item_id, 'text')
        new_path = Path(self.local_path_var.get()) / item_text if item_text != '..' else Path(self.local_path_var.get()).parent
        if new_path.is_dir():
            self.local_path_var.set(str(new_path)); self.refresh_local_files()

    def quest_tree_double_click(self, event): # ... (no changes)
        if not self.connected: return
        # <<< MODIFIED >>>
        if self.is_selecting_quest_move_destination:
            self.status_var.set("Navigating to Quest move destination... Use 'Set Current' or 'Cancel'.")

        item_id = self.quest_tree.focus()
        if not item_id: return
        item_text = self.quest_tree.item(item_id, 'text')
        item_type = self.quest_tree.item(item_id, 'values')[1]

        if item_text == '..': self.quest_up(); return
        if item_type == 'Directory':
            current_path = self.quest_path_var.get().rstrip('/')
            new_path = f"{current_path}/{item_text}" if current_path != '/' else f"/{item_text}"
            try:
                self._run_adb_command(['shell', f'ls "{new_path}"'], check=True, timeout=5)
                self.quest_path_var.set(new_path); self.refresh_quest_files()
            except Exception as e:
                messagebox.showerror("Navigation Error", f"Cannot access directory: {new_path}\n{e}")
    
    def toggle_checkbox(self, event): # ... (no changes)
        tree = event.widget
        item_id = tree.identify_row(event.y)
        column_id = tree.identify_column(event.x)
        if item_id and column_id == tree.column('checked', 'id'): 
            current_values = list(tree.item(item_id, 'values'))
            current_checked_state = current_values[2] 
            new_checked_state = '☑' if current_checked_state != '☑' else '☐'
            current_values[2] = new_checked_state
            tree.item(item_id, values=tuple(current_values))

    def refresh_local_files(self): # ... (no changes)
        for item in self.local_tree.get_children(): self.local_tree.delete(item)
        current_path_str = self.local_path_var.get()
        if not current_path_str:
            current_path_str = "C:\\" if os.name == 'nt' else str(Path.home())
            self.local_path_var.set(current_path_str)
        current_path = Path(current_path_str)
        
        if current_path.parent != current_path:
            self.local_tree.insert('', 'end', text='..', values=('', 'Parent Directory', '☐'))
        try:
            items = sorted(list(current_path.iterdir()), key=lambda x: (not x.is_dir(), x.name.lower()))
            for item in items:
                try:
                    if item.is_dir():
                        self.local_tree.insert('', 'end', text=item.name, values=('', 'Directory', '☐'))
                    elif item.is_file():
                        size = item.stat().st_size
                        size_str = f"{size/1024/1024:.1f} MB" if size >= 1024*1024 else f"{size/1024:.1f} KB" if size >= 1024 else f"{size} B"
                        self.local_tree.insert('', 'end', text=item.name, values=(size_str, 'File', '☐'))
                except OSError: continue
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list local '{current_path}': {e}")
    
    def refresh_quest_files(self): # ... (no changes)
        if not self.connected or not self.device_serial:
            for item in self.quest_tree.get_children(): self.quest_tree.delete(item)
            self._update_quest_move_ui_state() # Ensure move buttons are correctly set if disconnected
            return
        for item in self.quest_tree.get_children(): self.quest_tree.delete(item)
        quest_path = self.quest_path_var.get().rstrip('/') or "/storage/emulated/0"
        
        if quest_path != '/' and os.path.dirname(quest_path) != quest_path:
             self.quest_tree.insert('', 'end', text='..', values=('', 'Parent Directory', '☐'))
        try:
            cmd_str = f'ls -1Ap "{quest_path}/"' # -A: all except . and .., -p: append / to dirs, -1: one per line
            result = self._run_adb_command(['shell', cmd_str], timeout=10)
            if result.returncode != 0: 
                cmd_str_fallback = f'ls -1A "{quest_path}/"'
                result = self._run_adb_command(['shell', cmd_str_fallback], timeout=10)
                if result.returncode != 0:
                   raise Exception(f"Failed listing '{quest_path}': {result.stderr or result.stdout}")

            lines = result.stdout.strip().split('\n')
            if not lines or (len(lines) == 1 and not lines[0]): return

            files_info = [{'name': name.rstrip('/'), 'type': 'Directory' if name.endswith('/') else 'File', 'size': '?'}
                          for name in lines if name]
            sorted_files_info = sorted(files_info, key=lambda x: (x['type'] != 'Directory', x['name'].lower()))
            for info in sorted_files_info:
                self.quest_tree.insert('', 'end', text=info['name'], values=(info['size'], info['type'], '☐'))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list Quest files in '{quest_path}': {e}")
        finally:
            self._update_quest_move_ui_state() # Update button states after refresh

    def transfer_files(self, to_quest=True, selected_only=True): # ... (no changes)
        if not self.connected or not self.device_serial:
            messagebox.showerror("Error", "Please connect to Quest first"); return
        
        source_tree = self.local_tree if to_quest else self.quest_tree
        source_base_path = (self.local_path_var if to_quest else self.quest_path_var).get()
        dest_base_path = (self.quest_path_var if to_quest else self.local_path_var).get().rstrip('/')
        adb_verb = 'push' if to_quest else 'pull'
        items_to_transfer = []

        if selected_only:
            for item_id in source_tree.get_children():
                values = source_tree.item(item_id, 'values')
                if values and len(values) == 3 and values[2] == '☑':
                    name = source_tree.item(item_id, 'text')
                    if name == '..': continue
                    items_to_transfer.append({'name': name, 'is_dir': (values[1] == 'Directory')})
            if not items_to_transfer:
                messagebox.showerror("No Selection", "Please select items to transfer."); return
        else: 
            if to_quest: 
                for item in Path(source_base_path).iterdir():
                    items_to_transfer.append({'name': item.name, 'is_dir': item.is_dir()})
            else: 
                try:
                    result = self._run_adb_command(['shell', f'ls -1Ap "{source_base_path}/"'], timeout=10)
                    if result.returncode != 0: raise Exception(result.stderr or result.stdout)
                    for line in result.stdout.strip().split('\n'):
                        if line: items_to_transfer.append({'name': line.rstrip('/'), 'is_dir': line.endswith('/')})
                except Exception as e:
                    messagebox.showerror("Error Listing Quest Folder", f"Could not list {source_base_path}: {e}"); return
        if not items_to_transfer:
            messagebox.showinfo("Empty Folder", "Source folder is empty."); return

        if not messagebox.askyesno("Confirm Transfer", f"Transfer {len(items_to_transfer)} item(s) " +
                                 f"{'to Quest' if to_quest else 'from Quest'}?\nSource: {source_base_path}\nDest: {dest_base_path}"):
            return

        self.status_var.set(f"Transferring ({adb_verb})..."); self.root.update_idletasks()
        
        def transfer_thread_task():
            errors = []
            for item in items_to_transfer:
                src_full = str(Path(source_base_path) / item['name']) if to_quest else f"{source_base_path}/{item['name']}"
                dst_full = f"{dest_base_path}/{item['name']}" if to_quest else str(Path(dest_base_path) / item['name'])
                try:
                    if not to_quest and item['is_dir']: os.makedirs(dst_full, exist_ok=True)
                    result = self._run_adb_command([adb_verb, src_full, dst_full], timeout=300) # Increased timeout for large files
                    if result.returncode != 0: errors.append(f"Failed {item['name']}: {result.stderr or result.stdout}")
                except Exception as e: errors.append(f"Error {item['name']}: {e}")

            def show_results():
                if errors:
                    messagebox.showerror("Transfer Issues", f"Some items failed:\n" + "\n".join(errors[:5]))
                else:
                    messagebox.showinfo("Success", "Transfer completed.")
                self.status_var.set(f"Connected to {self.device_serial} ({self.connection_mode_var.get()})")
                if to_quest: self.refresh_quest_files()
                else: self.refresh_local_files()
            self.root.after(0, show_results)
        threading.Thread(target=transfer_thread_task, daemon=True).start()

    def delete_files(self, on_quest=False): # ... (no changes)
        if on_quest and (not self.connected or not self.device_serial):
            messagebox.showerror("Error", "Please connect to Quest first"); return
        # <<< MODIFIED >>> Cannot delete if in move destination selection mode
        if self.is_selecting_quest_move_destination:
            messagebox.showwarning("Action Blocked", "Cannot delete while selecting a move destination. Please cancel or complete the move operation.")
            return
            
        tree = self.quest_tree if on_quest else self.local_tree
        base_path = (self.quest_path_var if on_quest else self.local_path_var).get().rstrip('/')
        items_to_delete = []
        for item_id in tree.get_children():
            values = tree.item(item_id, 'values')
            if values and len(values) == 3 and values[2] == '☑':
                name = tree.item(item_id, 'text')
                if name == '..': continue
                items_to_delete.append({'name': name, 'is_dir': (values[1] == 'Directory' or values[1] == 'Parent Directory')})
        
        if not items_to_delete:
            messagebox.showerror("Error", "Please select items to delete."); return
        
        location = "Quest" if on_quest else "local computer"
        if not messagebox.askyesno("Confirm Delete", f"Delete {len(items_to_delete)} item(s) from {location} at {base_path}?\nTHIS IS PERMANENT!"):
            return

        self.status_var.set(f"Deleting from {location}..."); self.root.update_idletasks()

        def delete_thread_task():
            errors = []
            for item in items_to_delete:
                full_path_str = f"{base_path}/{item['name']}" if on_quest else str(Path(base_path) / item['name'])
                try:
                    if on_quest:
                        cmd = 'rm -rf' if item['is_dir'] else 'rm'
                        result = self._run_adb_command(['shell', cmd, f'"{full_path_str}"'], timeout=60)
                        if result.returncode != 0: errors.append(f"Failed Quest delete {item['name']}: {result.stderr or result.stdout}")
                    else:
                        if item['is_dir']: shutil.rmtree(full_path_str)
                        else: Path(full_path_str).unlink()
                except Exception as e: errors.append(f"Error deleting {item['name']}: {e}")

            def show_results():
                if errors: messagebox.showerror("Deletion Issues", "Some items failed:\n" + "\n".join(errors[:5]))
                else: messagebox.showinfo("Success", "Deletion completed.")
                self.status_var.set(f"Connected to {self.device_serial} ({self.connection_mode_var.get()})")
                if on_quest: self.refresh_quest_files()
                else: self.refresh_local_files()
            self.root.after(0, show_results)
        threading.Thread(target=delete_thread_task, daemon=True).start()

    # <<< NEW/MODIFIED METHODS FOR BROWSE-TO-DESTINATION MOVE >>>
    def _update_quest_move_ui_state(self):
        """Updates the visibility and text of move-related buttons."""
        if not self.connected: # If not connected, reset and hide move buttons
            self.is_selecting_quest_move_destination = False
            self.quest_move_source_items_info = []
            self.quest_move_source_base_path = ""

        if self.is_selecting_quest_move_destination and self.connected:
            self.move_quest_btn.config(text="Cancel Move Destination Select")
            self.set_destination_quest_btn.grid(row=2, column=0, padx=5, pady=2, sticky=tk.EW) # Show
            self.delete_quest_btn.config(state=tk.DISABLED) # Disable delete during move
            # Also disable transfer buttons
            self.transfer_selected_from_quest_btn.config(state=tk.DISABLED)
            self.transfer_folder_from_quest_btn.config(state=tk.DISABLED)
            self.transfer_selected_to_quest_btn.config(state=tk.DISABLED)
            self.transfer_folder_to_quest_btn.config(state=tk.DISABLED)

        else:
            self.move_quest_btn.config(text="Move Selected (Quest)")
            self.set_destination_quest_btn.grid_forget() # Hide
            if self.connected:
                self.delete_quest_btn.config(state=tk.NORMAL)
                self.transfer_selected_from_quest_btn.config(state=tk.NORMAL)
                self.transfer_folder_from_quest_btn.config(state=tk.NORMAL)
                self.transfer_selected_to_quest_btn.config(state=tk.NORMAL)
                self.transfer_folder_to_quest_btn.config(state=tk.NORMAL)
            else: # Not connected, ensure they are disabled
                self.delete_quest_btn.config(state=tk.DISABLED)
                self.transfer_selected_from_quest_btn.config(state=tk.DISABLED)
                self.transfer_folder_from_quest_btn.config(state=tk.DISABLED)
                self.transfer_selected_to_quest_btn.config(state=tk.DISABLED)
                self.transfer_folder_to_quest_btn.config(state=tk.DISABLED)


    def handle_move_quest_button_click(self):
        if not self.connected or not self.device_serial:
            messagebox.showerror("Error", "Please connect to Quest first")
            return

        if self.is_selecting_quest_move_destination:
            # Currently in destination selection mode, so this button acts as "Cancel"
            self._cancel_quest_move_destination_select_mode()
        else:
            # Initiate move: select source items
            self.quest_move_source_items_info = []
            self.quest_move_source_base_path = self.quest_path_var.get().rstrip('/')

            for item_id in self.quest_tree.get_children():
                values = self.quest_tree.item(item_id, 'values')
                if values and len(values) == 3 and values[2] == '☑':  # Checked
                    name = self.quest_tree.item(item_id, 'text')
                    if name == '..': continue
                    self.quest_move_source_items_info.append({'name': name})

            if not self.quest_move_source_items_info:
                messagebox.showerror("No Selection", "Please select files/folders on Quest to move.")
                return

            self.is_selecting_quest_move_destination = True
            self._update_quest_move_ui_state()
            self.status_var.set("Navigate to destination folder on Quest, then click 'Set Current as Move Destination'.")

    def _cancel_quest_move_destination_select_mode(self):
        self.is_selecting_quest_move_destination = False
        self.quest_move_source_items_info = []
        self.quest_move_source_base_path = ""
        self._update_quest_move_ui_state()
        if self.connected:
             self.status_var.set(f"Connected to {self.device_serial} ({self.connection_mode_var.get()})")
        else:
             self.status_var.set("Not Connected")


    def set_quest_move_destination(self):
        if not self.is_selecting_quest_move_destination:
            # Should not happen if UI is managed correctly
            messagebox.showerror("Error", "Not in destination selection mode.")
            self._cancel_quest_move_destination_select_mode()
            return

        destination_dir_quest = self.quest_path_var.get().rstrip('/')
        if not destination_dir_quest:
            messagebox.showerror("Invalid Path", "Destination path cannot be empty.")
            return
        if not destination_dir_quest.startswith('/'):
            messagebox.showerror("Invalid Path", "Destination path must be an absolute path (starting with '/').")
            return
        
        if destination_dir_quest == self.quest_move_source_base_path:
            # Check if any of the selected items would be moved into themselves (only relevant if a selected item *is* the dest_dir)
            # This is a bit complex if moving multiple items. Simpler check:
            # If source and dest base paths are the same, it's effectively a no-op for moving from a folder to itself.
            messagebox.showwarning("Invalid Operation", "Source and destination directories are the same. No items will be moved.")
            self._cancel_quest_move_destination_select_mode()
            return
        
        # Check if destination is a subfolder of any of the selected source folders
        for item_info in self.quest_move_source_items_info:
            source_item_full_path = f"{self.quest_move_source_base_path}/{item_info['name']}"
            # A simple string check is usually sufficient here for basic protection
            if destination_dir_quest.startswith(source_item_full_path + '/'):
                 # This check assumes the item being moved is a directory.
                 # A more robust check would involve `adb shell stat` for item types,
                 # but `mv` itself will usually prevent recursive moves.
                 messagebox.showerror("Invalid Destination",
                                      f"Cannot move '{item_info['name']}' into itself or one of its subdirectories ('{destination_dir_quest}').")
                 # Don't cancel mode yet, let user pick another destination or cancel
                 return


        item_names_to_move = [item['name'] for item in self.quest_move_source_items_info]
        confirmation_message = (
            f"Move {len(self.quest_move_source_items_info)} selected item(s):\n"
            f"{', '.join(item_names_to_move[:3])}{'...' if len(item_names_to_move) > 3 else ''}\n\n"
            f"From:\n{self.quest_move_source_base_path}/\n\n"
            f"To:\n{destination_dir_quest}/\n\n"
            "Confirm move on Quest?"
        )
        if not messagebox.askyesno("Confirm Move on Quest", confirmation_message, parent=self.root):
            # User cancelled the final confirmation, but stay in selection mode
            # Or, could choose to cancel selection mode:
            # self._cancel_quest_move_destination_select_mode()
            return

        self.status_var.set("Moving items on Quest...")
        self.root.update_idletasks()
        
        # Store items and paths before starting thread, as self. variables might change if user clicks cancel quickly
        items_to_process = list(self.quest_move_source_items_info) # Make a copy
        source_path_for_thread = str(self.quest_move_source_base_path)
        dest_path_for_thread = str(destination_dir_quest)

        # Crucially, exit destination selection mode *before* starting the thread
        # So the UI resets immediately and user can't click "Set Destination" again for this batch
        self._cancel_quest_move_destination_select_mode()

        threading.Thread(target=self._execute_quest_move_internal,
                         args=(items_to_process, source_path_for_thread, dest_path_for_thread),
                         daemon=True).start()


    def _execute_quest_move_internal(self, items_to_move_info, source_dir, dest_dir):
        errors_occurred = []
        success_count = 0

        for item_info in items_to_move_info:
            item_name = item_info['name']
            source_full_path = f"{source_dir}/{item_name}"
            
            shell_command_string = f'mv "{source_full_path}" "{dest_dir}/"' # Trailing slash helps mv treat dest as dir

            try:
                result = self._run_adb_command(['shell', shell_command_string], timeout=60)
                if result.returncode != 0:
                    err_msg = result.stderr or result.stdout or "Unknown ADB error"
                    # Filter out common "mv: <path>: directory not empty" if moving into existing folders,
                    # which is not an error for `mv source dest_folder/`
                    if not ("directory not empty" in err_msg.lower() and dest_dir in err_msg):
                        errors_occurred.append(f"Failed to move '{item_name}': {err_msg.strip()}")
                    else:
                        success_count +=1 # Treat "directory not empty" as success for this operation type
                else:
                    success_count += 1
            except subprocess.TimeoutExpired:
                errors_occurred.append(f"Timeout moving '{item_name}'")
            except Exception as e:
                errors_occurred.append(f"Error moving '{item_name}': {str(e)}")
        
        self.root.after(0, lambda: self._show_move_results(success_count, errors_occurred))

    def _show_move_results(self, success_count, errors_occurred): # No changes from previous version
        if errors_occurred:
            error_summary = "\n".join(errors_occurred[:5]) 
            if len(errors_occurred) > 5:
                error_summary += f"\n...and {len(errors_occurred)-5} more errors."
            messagebox.showerror(
                "Move Issues",
                f"Moved {success_count} item(s) successfully on Quest.\n"
                f"Some items failed to move:\n{error_summary}",
                parent=self.root
            )
        elif success_count > 0:
            messagebox.showinfo(
                "Move Success",
                f"Successfully moved {success_count} item(s) on the Quest.",
                parent=self.root
            )
        else: 
            messagebox.showinfo("Move Operation", "No items were moved or an issue occurred.", parent=self.root)

        # Restore normal status message and refresh
        if self.connected:
            try: # Check if widget exists before accessing connection_mode_var
                conn_mode = self.connection_mode_var.get()
                self.status_var.set(f"Connected to {self.device_serial} ({conn_mode})")
            except tk.TclError:
                self.status_var.set(f"Connected to {self.device_serial}") # Fallback
        else:
            self.status_var.set("Not Connected")
        
        self.refresh_quest_files()
        self._update_quest_move_ui_state() # Ensure UI is fully reset

if __name__ == "__main__":
    root = tk.Tk()
    app = OculusFileTransferGUI(root)
    root.mainloop()s
