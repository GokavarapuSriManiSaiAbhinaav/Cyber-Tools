import os
import time
import threading
import queue
import csv
import platform
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

class ForensicScannerLogic:
    """Handles the file system scanning and metadata collection logic (Backend)."""
    def __init__(self, target_dir, update_queue):
        self.target_dir = target_dir
        self.update_queue = update_queue
        self.is_scanning = False
        self.system = platform.system()
        self.total_size = 0
        self.total_files = 0

    def get_file_metadata(self, file_path, status="Active"):
        """Extracts and formats metadata for a single file path."""
        try:
            stat_info = os.stat(file_path)
            size = stat_info.st_size
            created_time = datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            modified_time = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            
            return {
                'file_name': os.path.basename(file_path),
                'full_path': file_path,
                'size': size,
                'created': created_time,
                'modified': modified_time,
                'status': status
            }
        except Exception:
            # Skip files with strict permission errors gracefully without breaking the loop
            return None

    def scan_directory(self):
        """Recursively scans the targeted active directory logic."""
        if not os.path.isdir(self.target_dir):
            self.update_queue.put(('ERROR', "Invalid or inaccessible directory selected."))
            return

        self.update_queue.put(('START_SCAN', None))
        
        # Traverse filesystem directory tree top-down
        for root, dirs, files in os.walk(self.target_dir):
            if not self.is_scanning:
                break
                
            for file in files:
                if not self.is_scanning:
                    break
                    
                full_path = os.path.join(root, file)
                metadata = self.get_file_metadata(full_path, "Active")
                
                if metadata:
                    self.total_size += metadata['size']
                    self.total_files += 1
                    # Pass the record string dictionary safely to the interface queue
                    self.update_queue.put(('FILE_RECORD', metadata))
                    
                    # Prevent overwhelming the main thread by limiting updates occasionally
                    if self.total_files % 50 == 0:
                        self.update_queue.put(('PROGRESS', (self.total_files, self.total_size)))

        self.is_scanning = False
        self.update_queue.put(('SCAN_DONE', (self.total_files, self.total_size)))

    def scan_deleted_files(self):
        """Scans the user's recycle bin for deleted files without native MFT recovery."""
        self.update_queue.put(('START_DELETED', None))
        
        recycle_paths = []
        # Support detection natively configured for Win/Mac/Linux
        if self.system == "Windows":
            recycle_paths = [r"C:\$Recycle.Bin"]
        elif self.system == "Linux":
            home = str(Path.home())
            recycle_paths = [os.path.join(home, ".local/share/Trash/files")]
        elif self.system == "Darwin": # macOS fallback
            home = str(Path.home())
            recycle_paths = [os.path.join(home, ".Trash")]

        found_any = False
        for recycle_dir in recycle_paths:
            if not os.path.exists(recycle_dir):
                continue
            
            try:
                found_any = True
                for root, dirs, files in os.walk(recycle_dir):
                    if not self.is_scanning:
                        break
                    
                    for file in files:
                        if not self.is_scanning:
                            break
                        full_path = os.path.join(root, file)
                        metadata = self.get_file_metadata(full_path, "Deleted")
                        
                        if metadata:
                            self.update_queue.put(('DELETED_RECORD', metadata))
            except PermissionError:
                # Permission logic handling for restricted system recycle partitions
                pass
                
        if not found_any:
            self.update_queue.put(('ERROR', "Recycle Bin / Trash directory not found or access denied. Ensure you are running with appropriate permissions."))

        self.is_scanning = False
        self.update_queue.put(('DELETED_DONE', None))

    def start_scan_thread(self, mode="Active"):
        """Initializes processing properties and detaches work mapping logic to a background daemon thread."""
        self.is_scanning = True
        self.total_size = 0
        self.total_files = 0
        
        target_func = self.scan_directory if mode == "Active" else self.scan_deleted_files
        threading.Thread(target=target_func, daemon=True).start()

    def stop_scan(self):
        self.is_scanning = False


class ForensicApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File System Forensic Analyzer")
        self.root.geometry("1100x750")
        
        # Modern Dark Theme Constants Setup
        self.bg_color = "#181818"
        self.panel_bg = "#222222"
        self.fg_color = "#eeeeee"
        self.entry_bg = "#333333"
        self.btn_bg = "#444444"
        self.active_color = "#4caf50"  # Vibrant Green
        self.deleted_color = "#f44336" # Red
        
        self.root.configure(bg=self.bg_color)
        
        # Model backend properties tracking logic
        self.scanner = None
        self.update_queue = queue.Queue()
        self.all_records = [] 
        
        # Internal sort states mapping logic
        self._sort_reverse = False
        self._sort_col = None
        
        self.setup_ui()
        self.check_queue()

    def setup_ui(self):
        """Constructs widgets, theme layouts and mapping grids mappings onto interface."""
        # Initialize native visually customizable ttk styles map
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure("Treeview", 
                        background=self.panel_bg,
                        foreground=self.fg_color,
                        fieldbackground=self.panel_bg,
                        rowheight=25,
                        bordercolor=self.bg_color,
                        borderwidth=0)
        style.map('Treeview', background=[('selected', '#555555')])
        
        style.configure("Treeview.Heading", 
                        background=self.btn_bg, 
                        foreground="#ffffff", 
                        font=('Helvetica', 10, 'bold'),
                        bordercolor=self.bg_color)

        # --- Top Action Frames Layout ---
        top_frame = tk.Frame(self.root, bg=self.bg_color)
        top_frame.pack(fill=tk.X, padx=15, pady=15)

        tk.Label(top_frame, text="Target Directory:", bg=self.bg_color, fg=self.fg_color, font=("Helvetica", 10, "bold")).grid(row=0, column=0, padx=(0, 10), pady=10, sticky="w")
        
        self.dir_var = tk.StringVar()
        self.dir_entry = tk.Entry(top_frame, textvariable=self.dir_var, width=55, bg=self.entry_bg, fg="#ffffff", insertbackground="white", font=("Courier", 10), bd=0, relief=tk.FLAT)
        self.dir_entry.grid(row=0, column=1, padx=10, pady=10)

        self.btn_browse = tk.Button(top_frame, text="Browse", command=self.browse_dir, bg=self.btn_bg, fg="#ffffff", relief=tk.FLAT, width=10, font=("Helvetica", 9, "bold"))
        self.btn_browse.grid(row=0, column=2, padx=5, pady=10)

        self.btn_scan = tk.Button(top_frame, text="Scan Directory", command=lambda: self.start_scan("Active"), bg="#1976d2", fg="#ffffff", relief=tk.FLAT, font=("Helvetica", 10, "bold"), width=15)
        self.btn_scan.grid(row=0, column=3, padx=10, pady=10)

        self.btn_deleted = tk.Button(top_frame, text="Show Deleted Files", command=lambda: self.start_scan("Deleted"), bg="#9c27b0", fg="#ffffff", relief=tk.FLAT, font=("Helvetica", 10, "bold"), width=18)
        self.btn_deleted.grid(row=0, column=4, padx=5, pady=10)

        # Filtering/Export Layout Rows Controls Mapping
        tk.Label(top_frame, text="Filter By:", bg=self.bg_color, fg=self.fg_color, font=("Helvetica", 10, "bold")).grid(row=1, column=0, padx=(0, 10), pady=0, sticky="w")
        
        self.filter_var = tk.StringVar(value="All Files")
        filter_menu = ttk.Combobox(top_frame, textvariable=self.filter_var, values=["All Files", "Recently Modified (7 Days)"], state="readonly", width=35)
        filter_menu.grid(row=1, column=1, padx=10, pady=0, sticky="w")
        filter_menu.bind("<<ComboboxSelected>>", self.apply_filter)
        
        self.btn_export = tk.Button(top_frame, text="Export CSV Report", command=self.export_csv, bg="#e65100", fg="#ffffff", relief=tk.FLAT, font=("Helvetica", 10, "bold"), width=18)
        self.btn_export.grid(row=1, column=4, padx=5, pady=0)

        # --- Middle Treeview Logic Area Layout ---
        mid_frame = tk.Frame(self.root, bg=self.bg_color)
        mid_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        columns = ("name", "path", "size", "created", "modified", "status")
        self.tree = ttk.Treeview(mid_frame, columns=columns, show="headings")

        # Map sorting algorithms commands callbacks
        self.tree.heading("name", text="File Name", command=lambda: self.sort_tree("name"))
        self.tree.heading("path", text="Full Path", command=lambda: self.sort_tree("path"))
        self.tree.heading("size", text="File Size (Bytes)", command=lambda: self.sort_tree("size"))
        self.tree.heading("created", text="Created Time", command=lambda: self.sort_tree("created"))
        self.tree.heading("modified", text="Modified Time", command=lambda: self.sort_tree("modified"))
        self.tree.heading("status", text="Status", command=lambda: self.sort_tree("status"))

        self.tree.column("name", width=180, anchor=tk.W)
        self.tree.column("path", width=350, anchor=tk.W)
        self.tree.column("size", width=100, anchor=tk.E)
        self.tree.column("created", width=140, anchor=tk.CENTER)
        self.tree.column("modified", width=140, anchor=tk.CENTER)
        self.tree.column("status", width=80, anchor=tk.CENTER)
        
        # Tags for colored mappings
        self.tree.tag_configure("active", foreground=self.active_color)
        self.tree.tag_configure("deleted", foreground=self.deleted_color)

        y_scrollbar = ttk.Scrollbar(mid_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=y_scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # --- Bottom Status and Details Progress UI Tracks Layout ---
        bottom_frame = tk.Frame(self.root, bg=self.panel_bg)
        bottom_frame.pack(fill=tk.X, padx=15, pady=(0, 15))

        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(bottom_frame, textvariable=self.status_var, bg=self.panel_bg, fg=self.fg_color, font=("Helvetica", 9), anchor="w").pack(side=tk.LEFT, padx=10, pady=5)

        self.progress_bar = ttk.Progressbar(bottom_frame, maximum=100, mode='indeterminate')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=20, pady=5)

        self.stats_var = tk.StringVar(value="Files mapped: 0  |  Size mapped: 0 MB")
        tk.Label(bottom_frame, textvariable=self.stats_var, bg=self.panel_bg, fg=self.fg_color, font=("Helvetica", 9, "bold")).pack(side=tk.RIGHT, padx=10, pady=5)

    def browse_dir(self):
        """Native map interface wrapper requesting directory queries logic string bindings."""
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.dir_var.set(dir_path)

    def format_size(self, size_bytes):
        return f"{size_bytes / (1024 * 1024):.2f} MB"

    def insert_record_to_tree(self, r):
        """Standard tree interface records injection maintaining native tag color mapping logic."""
        tag = "active" if r['status'] == "Active" else "deleted"
        self.tree.insert("", tk.END, values=(r['file_name'], r['full_path'], r['size'], r['created'], r['modified'], r['status']), tags=(tag,))
        if r not in self.all_records:
            self.all_records.append(r)

    def clear_tree(self):
        """Cleanly wipes UI logs without triggering threading lock bottlenecks."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.all_records.clear()

    def start_scan(self, mode="Active"):
        """Validates bindings and hooks into scanner execution context dispatching UI limits logic bounds dynamically."""
        if mode == "Active":
            target_dir = self.dir_var.get().strip()
            if not target_dir or not os.path.isdir(target_dir):
                messagebox.showerror("Error", "Please select a valid directory to scan.")
                return
            self.scanner = ForensicScannerLogic(target_dir, self.update_queue)
            self.clear_tree()
        else:
            self.scanner = ForensicScannerLogic("", self.update_queue)
        
        # UI Locking constraints locking controls while performing tasks
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_deleted.config(state=tk.DISABLED)
        self.btn_browse.config(state=tk.DISABLED)
        self.progress_bar.start(10)
        
        self.scanner.start_scan_thread(mode)

    def sort_tree(self, col):
        """In-place bidirectional sorting capability mapping logic binding natively mapping records dynamically."""
        if not self.all_records:
            return
            
        data = []
        for child in self.tree.get_children(''):
            val = self.tree.set(child, col)
            if col == "size":
                try:
                    val = int(val)
                except ValueError:
                    val = 0
            data.append((val, child))

        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_reverse = False
        self._sort_col = col

        data.sort(reverse=self._sort_reverse, key=lambda x: x[0])
        for index, (val, child) in enumerate(data):
            self.tree.move(child, '', index)

    def apply_filter(self, event=None):
        """Locally filters current records avoiding expensive backend re-scanning operations logic handling filters dynamically."""
        filter_type = self.filter_var.get()
        
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        if filter_type == "All Files":
            for r in self.all_records:
                self.insert_record_to_tree(r)
                
        elif filter_type == "Recently Modified (7 Days)":
            limit = time.time() - (7 * 24 * 60 * 60)
            for r in self.all_records:
                try:
                    mod_time_struct = time.strptime(r['modified'], '%Y-%m-%d %H:%M:%S')
                    if time.mktime(mod_time_struct) > limit:
                        self.insert_record_to_tree(r)
                except Exception:
                    pass

    def export_csv(self):
        """Writes current data locally securely handling character errors properly with mappings handling context dynamically."""
        if not self.all_records:
            messagebox.showinfo("Export", "No data to export. Please run a scan first.")
            return
            
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")], title="Export Report")
        if not file_path:
            return
            
        try:
            with open(file_path, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["File Name", "Full Path", "File Size (Bytes)", "Created Time", "Modified Time", "Status"])
                for r in self.all_records:
                    writer.writerow([r['file_name'], r['full_path'], r['size'], r['created'], r['modified'], r['status']])
            messagebox.showinfo("Export Success", f"Report successfully exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{e}")

    def check_queue(self):
        """Main loop threaded periodic dispatch bindings mapping data correctly."""
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()
                
                if msg_type == 'START_SCAN':
                    self.status_var.set("Scanning active directory... This may take a moment.")
                
                elif msg_type == 'START_DELETED':
                    self.status_var.set("Analyzing Recycle Bin properties... (Errors handling restricted paths inherently)")
                    
                elif msg_type == 'FILE_RECORD' or msg_type == 'DELETED_RECORD':
                    self.insert_record_to_tree(data)
                
                elif msg_type == 'PROGRESS':
                    count, size = data
                    self.stats_var.set(f"Files mapped: {count}  |  Size mapped: {self.format_size(size)}")
                
                elif msg_type == 'SCAN_DONE':
                    count, size = data
                    self.status_var.set("Directory sweep cleanly finished.")
                    self.stats_var.set(f"Files mapped: {count}  |  Size mapped: {self.format_size(size)}")
                    self.btn_scan.config(state=tk.NORMAL)
                    self.btn_deleted.config(state=tk.NORMAL)
                    self.btn_browse.config(state=tk.NORMAL)
                    self.progress_bar.stop()
                    
                elif msg_type == 'DELETED_DONE':
                    self.status_var.set("Deleted structural metadata parsing ended safely.")
                    self.btn_scan.config(state=tk.NORMAL)
                    self.btn_deleted.config(state=tk.NORMAL)
                    self.btn_browse.config(state=tk.NORMAL)
                    self.progress_bar.stop()
                    self.apply_filter()
                    
                elif msg_type == 'ERROR':
                    self.status_var.set("Operation halted safely due natively blocked directories constraints.")
                    self.btn_scan.config(state=tk.NORMAL)
                    self.btn_deleted.config(state=tk.NORMAL)
                    self.btn_browse.config(state=tk.NORMAL)
                    self.progress_bar.stop()
                    messagebox.showerror("Directory Issue", data)
                    
        except queue.Empty:
            pass
            
        self.root.after(100, self.check_queue)


if __name__ == "__main__":
    app_root = tk.Tk()
    app = ForensicApp(app_root)
    app_root.mainloop()
